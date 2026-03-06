{{/*
Expand the name of the chart.
*/}}
{{- define "clawdstrike.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "clawdstrike.fullname" -}}
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

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "clawdstrike.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Namespace to deploy into.
*/}}
{{- define "clawdstrike.namespace" -}}
{{- if .Values.global.namespace }}
{{- .Values.global.namespace }}
{{- else if .Values.namespace.name }}
{{- .Values.namespace.name }}
{{- else }}
{{- .Release.Namespace }}
{{- end }}
{{- end }}

{{/*
Common labels applied to all resources.
*/}}
{{- define "clawdstrike.labels" -}}
helm.sh/chart: {{ include "clawdstrike.chart" . }}
{{ include "clawdstrike.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: clawdstrike
{{- end }}

{{/*
Selector labels.
*/}}
{{- define "clawdstrike.selectorLabels" -}}
app.kubernetes.io/name: {{ include "clawdstrike.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Component labels - extends common labels with a component identifier.
*/}}
{{- define "clawdstrike.componentLabels" -}}
{{ include "clawdstrike.labels" .ctx }}
app.kubernetes.io/component: {{ .component }}
{{- end }}

{{/*
Component selector labels.
*/}}
{{- define "clawdstrike.componentSelectorLabels" -}}
{{ include "clawdstrike.selectorLabels" .ctx }}
app.kubernetes.io/component: {{ .component }}
{{- end }}

{{/*
ServiceAccount name.
*/}}
{{- define "clawdstrike.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "clawdstrike.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
NATS URL - returns either the external URL or the internal service URL.
*/}}
{{- define "clawdstrike.natsUrl" -}}
{{- if .Values.nats.external.enabled }}
{{- .Values.nats.external.url }}
{{- else }}
{{- printf "nats://%s-nats:4222" (include "clawdstrike.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Agent-facing NATS URL returned by control-api enrollment responses.
*/}}
{{- define "clawdstrike.agentNatsUrl" -}}
{{- if .Values.controlApi.agentNatsUrl }}
{{- .Values.controlApi.agentNatsUrl }}
{{- else }}
{{- include "clawdstrike.natsUrl" . }}
{{- end }}
{{- end }}

{{/*
Control API service name.
*/}}
{{- define "clawdstrike.controlApiName" -}}
{{- printf "%s-control-api" (include "clawdstrike.fullname" .) }}
{{- end }}

{{/*
Embedded Postgres service name for control-api.
*/}}
{{- define "clawdstrike.controlApiPostgresName" -}}
{{- printf "%s-postgres" (include "clawdstrike.controlApiName" .) }}
{{- end }}

{{/*
Control API database URL.
*/}}
{{- define "clawdstrike.controlApiDatabaseUrl" -}}
{{- if .Values.controlApi.databaseUrl }}
{{- .Values.controlApi.databaseUrl }}
{{- else if .Values.controlApi.postgres.enabled }}
{{- printf "postgres://%s:%s@%s:5432/%s" .Values.controlApi.postgres.username .Values.controlApi.postgres.password (include "clawdstrike.controlApiPostgresName" .) .Values.controlApi.postgres.database }}
{{- else }}
{{- "" }}
{{- end }}
{{- end }}

{{/*
Image pull secrets.
*/}}
{{- define "clawdstrike.imagePullSecrets" -}}
{{- with .Values.global.imagePullSecrets }}
imagePullSecrets:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end }}

{{/*
Global pod scheduling controls shared by all workloads.
*/}}
{{- define "clawdstrike.globalScheduling" -}}
{{- with .Values.global.nodeSelector }}
nodeSelector:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .Values.global.tolerations }}
tolerations:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end }}

{{/*
Spine image tag - uses the per-component convention or falls back to appVersion.
*/}}
{{- define "clawdstrike.spineImageTag" -}}
{{- if .Values.spine.image.tag }}
{{- .Values.spine.image.tag }}
{{- else }}
{{- printf "spine-%s-%s" .component .Chart.AppVersion }}
{{- end }}
{{- end }}
