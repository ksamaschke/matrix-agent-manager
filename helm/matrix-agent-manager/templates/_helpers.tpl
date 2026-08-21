{{- define "matrix-agent-manager.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "matrix-agent-manager.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name (include "matrix-agent-manager.name" .) | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{- define "matrix-agent-manager.serviceAccountName" -}}
{{- default (include "matrix-agent-manager.fullname" .) .Values.serviceAccount.name -}}
{{- end -}}

{{- define "matrix-agent-manager.secretNamespace" -}}
{{- default (default .Release.Namespace .Values.config.secretBackend.namespace) .Values.rbac.secretNamespace -}}
{{- end -}}

{{- define "matrix-agent-manager.labels" -}}
app.kubernetes.io/name: {{ include "matrix-agent-manager.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: matrix-agent-manager
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | quote }}
{{- end }}

{{- define "matrix-agent-manager.selectorLabels" -}}
app.kubernetes.io/name: {{ include "matrix-agent-manager.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
