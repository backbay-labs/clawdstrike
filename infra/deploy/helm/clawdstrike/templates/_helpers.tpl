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
Image pull secrets.
*/}}
{{- define "clawdstrike.imagePullSecrets" -}}
{{- with .Values.global.imagePullSecrets }}
imagePullSecrets:
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
