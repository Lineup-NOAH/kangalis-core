{{/* Chart adı (override edilebilir). */}}
{{- define "kangalis.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Tam ad: release-chart (fullnameOverride önceliklidir). */}}
{{- define "kangalis.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "kangalis.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Ortak etiketler. */}}
{{- define "kangalis.labels" -}}
helm.sh/chart: {{ include "kangalis.chart" . }}
{{ include "kangalis.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "kangalis.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kangalis.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "kangalis.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "kangalis.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* Postgres servis ana adı (küme içi). */}}
{{- define "kangalis.postgresHost" -}}
{{- printf "%s-postgres" (include "kangalis.fullname" .) -}}
{{- end -}}

{{/* DATABASE_URL: küme içi postgres ya da dış URL. */}}
{{- define "kangalis.databaseUrl" -}}
{{- if .Values.postgres.enabled -}}
{{- printf "postgresql+asyncpg://%s:%s@%s:5432/%s" .Values.postgres.user .Values.postgres.password (include "kangalis.postgresHost" .) .Values.postgres.database -}}
{{- else -}}
{{- required "postgres.enabled=false iken externalDatabaseUrl zorunlu" .Values.externalDatabaseUrl -}}
{{- end -}}
{{- end -}}

{{/* REDIS_URL: küme içi redis ya da dış URL. */}}
{{- define "kangalis.redisUrl" -}}
{{- if .Values.redis.enabled -}}
{{- printf "redis://%s-redis:6379/0" (include "kangalis.fullname" .) -}}
{{- else -}}
{{- required "redis.enabled=false iken externalRedisUrl zorunlu" .Values.externalRedisUrl -}}
{{- end -}}
{{- end -}}

{{/* Uygulama imajı (app/worker/beat/mcp ortak). */}}
{{- define "kangalis.image" -}}
{{- printf "%s:%s" .Values.image.repository (.Values.image.tag | default .Chart.AppVersion) -}}
{{- end -}}
