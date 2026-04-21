// pg-jwt-proxy: A Postgres wire-protocol proxy that accepts OIDC JWT tokens as passwords.
//
// Flow per connection:
//   1. Client connects with standard Postgres driver (psql, pgx, psycopg2, etc.)
//   2. Proxy sends AuthenticationCleartextPassword challenge
//   3. Client sends its Keycloak JWT as the password field
//   4. Proxy validates JWT signature against Keycloak JWKS, checks expiry + issuer
//   5. Proxy connects to upstream Postgres as the "authenticator" service account
//   6. Proxy issues SET ROLE <preferred_username> — Row Level Security kicks in
//   7. Proxy sends AuthenticationOk to client, then pipes bytes transparently
//
// This is conceptually identical to how Teleport Database Access works:
//   - Identity (cert/JWT) is the credential, not a static password
//   - The proxy maps identity → database role → RLS-enforced data access
//   - No application ever holds a long-lived database password
package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgproto3/v2"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// keySource wraps either a live JWKS HTTP cache or a static key set loaded from a file.
// The file path case is used in k8s where an init container writes the JWKS to a volume.
type keySource struct {
	// one of these is set
	cache    *jwk.Cache
	static   jwk.Set
	jwksURL  string // only used with cache
}

type config struct {
	listenAddr string
	pgHost     string
	pgPort     string
	pgUser     string
	pgPassword string
	pgDatabase string
	jwksURL    string
	issuer     string
	roleClaim  string
}

func loadConfig() config {
	rawURL := getEnv("POSTGRES_URL", "postgres://authenticator:changeme@localhost:5432/app?sslmode=disable")
	u, err := url.Parse(rawURL)
	if err != nil {
		log.Fatalf("invalid POSTGRES_URL: %v", err)
	}
	port := u.Port()
	if port == "" {
		port = "5432"
	}
	pass, _ := u.User.Password()
	return config{
		listenAddr: getEnv("PROXY_LISTEN_ADDR", ":5432"),
		pgHost:     u.Hostname(),
		pgPort:     port,
		pgUser:     u.User.Username(),
		pgPassword: pass,
		pgDatabase: strings.TrimPrefix(u.Path, "/"),
		jwksURL:    getEnv("KEYCLOAK_JWKS_URL", "http://keycloak:8180/realms/demo/protocol/openid-connect/certs"),
		issuer:     getEnv("JWT_ISSUER", ""),
		roleClaim:  getEnv("JWT_ROLE_CLAIM", "preferred_username"),
	}
}

type proxy struct {
	cfg  config
	keys keySource
}

// loadKeySource builds a keySource from a URL.
// file:///path reads the JWKS once from disk (used in k8s with a volume-mounted JWKS).
// http(s):// sets up a live cache with auto-refresh.
func loadKeySource(ctx context.Context, rawURL string) (keySource, error) {
	if strings.HasPrefix(rawURL, "file://") {
		path := strings.TrimPrefix(rawURL, "file://")
		data, err := os.ReadFile(path)
		if err != nil {
			return keySource{}, fmt.Errorf("read JWKS file %s: %w", path, err)
		}
		set, err := jwk.Parse(data)
		if err != nil {
			return keySource{}, fmt.Errorf("parse JWKS file: %w", err)
		}
		log.Printf("loaded JWKS from file %s (%d keys)", path, set.Len())
		return keySource{static: set}, nil
	}

	cache := jwk.NewCache(ctx)
	if err := cache.Register(rawURL, jwk.WithRefreshInterval(5*time.Minute)); err != nil {
		return keySource{}, fmt.Errorf("register JWKS cache: %w", err)
	}
	log.Printf("warming JWKS cache from %s", rawURL)
	for {
		if _, err := cache.Refresh(ctx, rawURL); err == nil {
			break
		} else {
			log.Printf("JWKS not ready: %v — retrying in 5s", err)
			time.Sleep(5 * time.Second)
		}
	}
	log.Println("JWKS ready")
	return keySource{cache: cache, jwksURL: rawURL}, nil
}

func (ks keySource) get(ctx context.Context) (jwk.Set, error) {
	if ks.static != nil {
		return ks.static, nil
	}
	return ks.cache.Get(ctx, ks.jwksURL)
}

func main() {
	cfg := loadConfig()
	ctx := context.Background()

	keys, err := loadKeySource(ctx, cfg.jwksURL)
	if err != nil {
		log.Fatalf("load JWKS: %v", err)
	}

	p := &proxy{cfg: cfg, keys: keys}

	ln, err := net.Listen("tcp", cfg.listenAddr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("pg-jwt-proxy listening on %s (upstream: %s:%s)", cfg.listenAddr, cfg.pgHost, cfg.pgPort)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go p.handle(conn)
	}
}

func (p *proxy) handle(clientConn net.Conn) {
	defer clientConn.Close()
	addr := clientConn.RemoteAddr()

	backend := pgproto3.NewBackend(pgproto3.NewChunkReader(clientConn), clientConn)

	// Receive startup message, declining SSL if offered
	startup, err := p.receiveStartup(clientConn, backend)
	if err != nil {
		log.Printf("[%s] startup: %v", addr, err)
		return
	}

	user := startup.Parameters["user"]
	database := startup.Parameters["database"]
	if database == "" {
		database = p.cfg.pgDatabase
	}
	log.Printf("[%s] connect: user=%s database=%s", addr, user, database)

	// Ask for password (which will be a JWT)
	if err := backend.Send(&pgproto3.AuthenticationCleartextPassword{}); err != nil {
		log.Printf("[%s] send auth challenge: %v", addr, err)
		return
	}

	msg, err := backend.Receive()
	if err != nil {
		log.Printf("[%s] receive password: %v", addr, err)
		return
	}
	pwMsg, ok := msg.(*pgproto3.PasswordMessage)
	if !ok {
		sendAuthError(backend, "08P01", "expected password message")
		return
	}

	// Validate JWT — this is the identity enforcement step
	role, err := p.validateJWT(pwMsg.Password)
	if err != nil {
		log.Printf("[%s] JWT rejected: %v", addr, err)
		sendAuthError(backend, "28000", "authentication failed: invalid or expired token")
		return
	}
	log.Printf("[%s] JWT valid → role=%s", addr, role)

	// Connect to upstream Postgres and apply the identity via SET ROLE
	upstreamConn, params, err := p.connectUpstream(database, role)
	if err != nil {
		log.Printf("[%s] upstream connect: %v", addr, err)
		sendAuthError(backend, "08006", "upstream database connection failed")
		return
	}
	defer upstreamConn.Close()

	// Auth OK — complete the handshake with the client
	if err := backend.Send(&pgproto3.AuthenticationOk{}); err != nil {
		log.Printf("[%s] send AuthOk: %v", addr, err)
		return
	}
	// Forward Postgres runtime parameters so clients can read server_version etc.
	for k, v := range params {
		backend.Send(&pgproto3.ParameterStatus{Name: k, Value: v})
	}
	// Proxy doesn't support cancel requests, send zero key data
	backend.Send(&pgproto3.BackendKeyData{ProcessID: 0, SecretKey: 0})
	if err := backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'}); err != nil {
		log.Printf("[%s] send ReadyForQuery: %v", addr, err)
		return
	}

	log.Printf("[%s] authenticated as %s — proxying", addr, role)

	// Transparent bidirectional byte pipe — we don't inspect query content
	done := make(chan struct{}, 2)
	go func() { io.Copy(upstreamConn, clientConn); done <- struct{}{} }()
	go func() { io.Copy(clientConn, upstreamConn); done <- struct{}{} }()
	<-done
	log.Printf("[%s] connection closed (role=%s)", addr, role)
}

// receiveStartup reads the startup message, declining SSL if the client requests it.
func (p *proxy) receiveStartup(conn net.Conn, backend *pgproto3.Backend) (*pgproto3.StartupMessage, error) {
	msg, err := backend.ReceiveStartupMessage()
	if err != nil {
		return nil, err
	}
	if _, ok := msg.(*pgproto3.SSLRequest); ok {
		conn.Write([]byte{'N'}) // no SSL — TLS termination should happen at the ingress layer
		msg, err = backend.ReceiveStartupMessage()
		if err != nil {
			return nil, err
		}
	}
	startup, ok := msg.(*pgproto3.StartupMessage)
	if !ok {
		return nil, fmt.Errorf("unexpected message type %T", msg)
	}
	return startup, nil
}

// validateJWT verifies the token's signature against the cached JWKS and returns
// the value of the configured role claim (default: preferred_username).
func (p *proxy) validateJWT(tokenStr string) (string, error) {
	ctx := context.Background()

	keySet, err := p.keys.get(ctx)
	if err != nil {
		return "", fmt.Errorf("get JWKS: %w", err)
	}

	opts := []jwt.ParseOption{
		jwt.WithKeySet(keySet),
		jwt.WithValidate(true),
	}
	if p.cfg.issuer != "" {
		opts = append(opts, jwt.WithIssuer(p.cfg.issuer))
	}

	token, err := jwt.ParseString(tokenStr, opts...)
	if err != nil {
		return "", err
	}

	val, ok := token.Get(p.cfg.roleClaim)
	if !ok {
		return "", fmt.Errorf("claim %q not found in token", p.cfg.roleClaim)
	}
	role, ok := val.(string)
	if !ok || role == "" {
		return "", fmt.Errorf("claim %q is not a non-empty string", p.cfg.roleClaim)
	}
	return role, nil
}

// connectUpstream opens a raw TCP connection to Postgres, completes the wire-protocol
// handshake as the authenticator service account, then issues SET ROLE to enforce the
// JWT-derived identity before handing the connection back for transparent proxying.
func (p *proxy) connectUpstream(database, role string) (net.Conn, map[string]string, error) {
	conn, err := net.DialTimeout("tcp", p.cfg.pgHost+":"+p.cfg.pgPort, 10*time.Second)
	if err != nil {
		return nil, nil, fmt.Errorf("dial %s:%s: %w", p.cfg.pgHost, p.cfg.pgPort, err)
	}

	frontend := pgproto3.NewFrontend(pgproto3.NewChunkReader(conn), conn)

	if err := frontend.Send(&pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersionNumber,
		Parameters: map[string]string{
			"user":             p.cfg.pgUser,
			"database":         database,
			"application_name": fmt.Sprintf("pg-jwt-proxy[%s]", role),
		},
	}); err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("send startup: %w", err)
	}

	// Complete the Postgres startup handshake
	params := map[string]string{}
	for {
		msg, err := frontend.Receive()
		if err != nil {
			conn.Close()
			return nil, nil, fmt.Errorf("upstream startup: %w", err)
		}
		switch m := msg.(type) {
		case *pgproto3.AuthenticationCleartextPassword:
			if err := frontend.Send(&pgproto3.PasswordMessage{Password: p.cfg.pgPassword}); err != nil {
				conn.Close()
				return nil, nil, err
			}
		case *pgproto3.AuthenticationOk:
			// trust auth or password accepted — continue reading startup params
		case *pgproto3.AuthenticationSASL:
			conn.Close()
			return nil, nil, fmt.Errorf("SCRAM auth not supported — set pg_hba.conf to trust or md5 for the proxy connection")
		case *pgproto3.ParameterStatus:
			params[m.Name] = m.Value
		case *pgproto3.BackendKeyData:
			// ignored — we don't support cancel requests
		case *pgproto3.ReadyForQuery:
			goto startup_done
		case *pgproto3.ErrorResponse:
			conn.Close()
			return nil, nil, fmt.Errorf("postgres rejected connection: %s", m.Message)
		}
	}

startup_done:
	// Enforce identity: SET ROLE causes RLS policies to filter data by the JWT-identified user.
	// This is the database-layer identity enforcement — equivalent to Teleport mapping your
	// SSO identity to a database user on each new connection.
	setRoleSQL := "SET ROLE " + quoteIdent(role)
	if err := frontend.Send(&pgproto3.Query{String: setRoleSQL}); err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("send SET ROLE: %w", err)
	}

	for {
		msg, err := frontend.Receive()
		if err != nil {
			conn.Close()
			return nil, nil, fmt.Errorf("SET ROLE response: %w", err)
		}
		switch m := msg.(type) {
		case *pgproto3.CommandComplete:
			// SET succeeded
		case *pgproto3.ReadyForQuery:
			_ = m
			goto role_set
		case *pgproto3.ErrorResponse:
			conn.Close()
			return nil, nil, fmt.Errorf("SET ROLE %s rejected: %s (role may not exist in postgres)", role, m.Message)
		}
	}

role_set:
	// Return the raw conn. After SET ROLE + ReadyForQuery, the protocol is synchronous
	// so pgproto3's ChunkReader buffer is empty — safe to pipe conn directly.
	return conn, params, nil
}

func sendAuthError(backend *pgproto3.Backend, code, msg string) {
	backend.Send(&pgproto3.ErrorResponse{
		Severity:            "FATAL",
		SeverityUnlocalized: "FATAL",
		Code:                code,
		Message:             msg,
	})
}

// quoteIdent safely double-quotes a Postgres identifier to prevent injection.
func quoteIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
