{{- define "envoy.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "envoy.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "envoy.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | quote }}
{{ include "envoy.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "envoy.selectorLabels" -}}
app.kubernetes.io/name: {{ include "envoy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/* Keycloak JWKS URI */}}
{{- define "envoy.keycloakJwksUri" -}}
{{- printf "%s/realms/%s/protocol/openid-connect/certs" .Values.keycloak.url .Values.keycloak.realm }}
{{- end }}

{{/* Keycloak issuer (must match iss claim in JWT) */}}
{{- define "envoy.keycloakIssuer" -}}
{{- printf "%s/realms/%s" .Values.keycloak.url .Values.keycloak.realm }}
{{- end }}
