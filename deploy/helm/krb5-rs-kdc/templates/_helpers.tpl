{{/* Chart name. */}}
{{- define "krb5-rs-kdc.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Fully qualified app name. */}}
{{- define "krb5-rs-kdc.fullname" -}}
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

{{- define "krb5-rs-kdc.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Labels selecting every pod of this release. */}}
{{- define "krb5-rs-kdc.selectorLabels" -}}
app.kubernetes.io/name: {{ include "krb5-rs-kdc.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/* Labels selecting the KDC pods (primary and replicas) for the kdc Service. */}}
{{- define "krb5-rs-kdc.kdcSelectorLabels" -}}
{{ include "krb5-rs-kdc.selectorLabels" . }}
krb5-rs.io/kdc: "true"
{{- end }}

{{- define "krb5-rs-kdc.labels" -}}
helm.sh/chart: {{ include "krb5-rs-kdc.chart" . }}
{{ include "krb5-rs-kdc.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/* Container image: digest wins over tag. */}}
{{- define "krb5-rs-kdc.image" -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}
{{- end }}

{{- define "krb5-rs-kdc.secretName" -}}
{{- default (include "krb5-rs-kdc.fullname" .) .Values.secrets.existingSecret }}
{{- end }}

{{/* Service name of the primary (propagation + KDC port for replicas). */}}
{{- define "krb5-rs-kdc.primaryService" -}}
{{- printf "%s-primary" (include "krb5-rs-kdc.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Scheduling shared by primary and replicas: user affinity wins, otherwise a
preferred anti-affinity over all KDC pods on the hostname.
Args: dict "ctx" root "cfg" component values.
*/}}
{{- define "krb5-rs-kdc.scheduling" -}}
{{- $ctx := .ctx }}
{{- with .cfg.nodeSelector }}
nodeSelector:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .cfg.tolerations }}
tolerations:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- if .cfg.affinity }}
affinity:
  {{- toYaml .cfg.affinity | nindent 2 }}
{{- else if $ctx.Values.topology.antiAffinity.enabled }}
affinity:
  podAntiAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
      - weight: 100
        podAffinityTerm:
          topologyKey: kubernetes.io/hostname
          labelSelector:
            matchLabels:
              {{- include "krb5-rs-kdc.kdcSelectorLabels" $ctx | nindent 14 }}
{{- end }}
{{- if $ctx.Values.topology.spread.enabled }}
topologySpreadConstraints:
  - maxSkew: 1
    topologyKey: {{ $ctx.Values.topology.spread.topologyKey }}
    whenUnsatisfiable: ScheduleAnyway
    labelSelector:
      matchLabels:
        {{- include "krb5-rs-kdc.kdcSelectorLabels" $ctx | nindent 8 }}
{{- end }}
{{- with $ctx.Values.priorityClassName }}
priorityClassName: {{ . }}
{{- end }}
{{- end }}

{{/* kdc.conf for a role ("primary" or "replica"). Args: dict "ctx" "role". */}}
{{- define "krb5-rs-kdc.kdcConf" -}}
{{- $ctx := .ctx }}
{{- $v := $ctx.Values }}
{{- $realm := required "realm is required" $v.realm }}
[kdcdefaults]
 kdc_ports = {{ $v.kdc.containerPort }}
 kdc_tcp_ports = {{ $v.kdc.containerPort }}

[realms]
 {{ $realm }} = {
  database_name = /var/lib/krb5-rs/principal
  key_stash_file = /var/lib/krb5-rs/stash
  max_life = {{ $v.kdc.maxLife }}
  max_renewable_life = {{ $v.kdc.maxRenewableLife }}
  supported_enctypes = {{ $v.kdc.supportedEnctypes }}
  kprop_service = {{ $v.propagation.servicePrincipal }}
  kprop_client = {{ $v.propagation.clientPrincipal }}
{{- if eq .role "primary" }}
  kprop_listen = 0.0.0.0:{{ $v.propagation.port }}
{{- else }}
  kprop_primary = {{ include "krb5-rs-kdc.primaryService" $ctx }}:{{ $v.propagation.port }}
  kprop_primary_kdc = {{ include "krb5-rs-kdc.primaryService" $ctx }}:{{ $v.kdc.containerPort }}
  kprop_password_file = /secrets/kprop-password
  kprop_poll_interval = {{ $v.propagation.pollInterval }}
{{- end }}
 }
{{- with $v.kdc.extraKdcConf }}

{{ . }}
{{- end }}
{{- end }}
