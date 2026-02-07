{{/*
Chart name
*/}}
{{- define "cert-guardian.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Fullname
*/}}
{{- define "cert-guardian.fullname" -}}
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
Common labels
*/}}
{{- define "cert-guardian.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version | replace "+" "_" }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{ include "cert-guardian.selectorLabels" . }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "cert-guardian.selectorLabels" -}}
app.kubernetes.io/name: {{ include "cert-guardian.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Backend selector labels
*/}}
{{- define "cert-guardian.backendSelectorLabels" -}}
{{ include "cert-guardian.selectorLabels" . }}
app.kubernetes.io/component: backend
{{- end }}

{{/*
Frontend selector labels
*/}}
{{- define "cert-guardian.frontendSelectorLabels" -}}
{{ include "cert-guardian.selectorLabels" . }}
app.kubernetes.io/component: frontend
{{- end }}

{{/*
Scanner selector labels
*/}}
{{- define "cert-guardian.scannerSelectorLabels" -}}
{{ include "cert-guardian.selectorLabels" . }}
app.kubernetes.io/component: scanner
{{- end }}
