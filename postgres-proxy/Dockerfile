FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY main.go .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o pg-jwt-proxy .

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=builder /app/pg-jwt-proxy /usr/local/bin/
EXPOSE 5432
ENTRYPOINT ["pg-jwt-proxy"]
