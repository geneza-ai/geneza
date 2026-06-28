{{/* Standard name helpers. */}}
{{- define "geneza-controller.name" -}}
{{- default "geneza-controller" .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "geneza-controller.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default "geneza-controller" .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "geneza-controller.labels" -}}
app.kubernetes.io/name: {{ include "geneza-controller.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
{{- end -}}

{{- define "geneza-controller.selectorLabels" -}}
app.kubernetes.io/name: {{ include "geneza-controller.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "geneza-controller.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "geneza-controller.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "geneza-controller.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}

{{- define "geneza-controller.gatewayName" -}}
{{- default (include "geneza-controller.fullname" .) .Values.gateway.name -}}
{{- end -}}

{{- define "geneza-controller.consoleTLSSecret" -}}
{{- default (printf "%s-console-tls" (include "geneza-controller.fullname" .)) .Values.gateway.consoleTLS.secretName -}}
{{- end -}}
