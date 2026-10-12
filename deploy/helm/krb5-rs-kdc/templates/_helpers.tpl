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

{{- define "krb5-rs-kdc.fileConfigChecksum" -}}
{{- include (print $.Template.BasePath "/configmap.yaml") . | replace (printf "helm.sh/chart: %s" (include "krb5-rs-kdc.chart" .)) (printf "helm.sh/chart: %s-%s" .Chart.Name (.Chart.AppVersion | replace "+" "_")) | sha256sum }}
{{- end }}

{{/* Container image: digest wins over tag. */}}
{{- define "krb5-rs-kdc.image" -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- if and (eq .Values.database.mode "cockroach") (not .Values.image.tag) -}}
{{- $tag = printf "%s-cockroach" .Chart.AppVersion -}}
{{- end -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
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
Shared CockroachDB module stanza. Args: dict "ctx" root "url" URL "certDir" path.
Set "kdc" to include the KDC replication and local-replica options.
*/}}
{{- define "krb5-rs-kdc.cockroachDbmodule" -}}
{{- $v := .ctx.Values }}
[dbmodules]
 crdb = {
  db_library = krb5-rs-cockroach
  cockroach_url = {{ required "CockroachDB URL is required" .url }}
  cockroach_ca = {{ .certDir }}/ca.crt
  cockroach_cert = {{ .certDir }}/tls.crt
  cockroach_key = {{ .certDir }}/tls.key
  cockroach_pool_size = {{ $v.cockroach.poolSize }}
  cockroach_pool_idle_timeout = {{ $v.cockroach.poolIdleTimeout }}
  cockroach_connect_timeout = {{ $v.cockroach.connectTimeout }}
  cockroach_statement_timeout = {{ $v.cockroach.statementTimeout }}
  cockroach_transaction_timeout = {{ $v.cockroach.transactionTimeout }}
{{- if .kdc }}
  replication_read = {{ $v.cockroach.replicationRead }}
  replica_path = /var/lib/krb5-rs/replica
  turso_pool_size = {{ $v.cockroach.turso.poolSize }}
  region = {{ required "cockroach.region is required" $v.cockroach.region }}
  consistency_mode = {{ $v.cockroach.consistencyMode }}
  max_staleness = {{ $v.cockroach.maxStaleness }}
  authoritative_timeout = {{ $v.cockroach.authoritativeTimeout }}
  replication_poll_interval = {{ $v.cockroach.replication.pollInterval }}
  replication_batch_limit = {{ $v.cockroach.replication.batchLimit }}
  replication_retry_min = {{ $v.cockroach.replication.retryMin }}
  replication_retry_max = {{ $v.cockroach.replication.retryMax }}
  replication_rebuild = {{ $v.cockroach.replication.rebuild }}
  replication_heartbeat_interval = {{ $v.cockroach.replication.heartbeatInterval }}
{{- end }}
 }
{{- end }}

{{- define "krb5-rs-kdc.cockroachClientConf" -}}
{{- $v := .ctx.Values }}
[realms]
 {{ required "realm is required" $v.realm }} = {
  database_module = crdb
  supported_enctypes = {{ $v.kdc.supportedEnctypes }}
 }

{{ include "krb5-rs-kdc.cockroachDbmodule" (dict "ctx" .ctx "url" .url "certDir" .certDir "kdc" false) }}
{{- end }}

{{- define "krb5-rs-kdc.krb5Conf" -}}
{{- $v := .Values }}
[libdefaults]
 default_realm = {{ required "realm is required" $v.realm }}
 dns_lookup_kdc = false
 dns_lookup_realm = false
{{- if $v.kdc.domainRealm }}

[domain_realm]
{{- range $domain, $realm := $v.kdc.domainRealm }}
 {{ $domain }} = {{ $realm }}
{{- end }}
{{- end }}
{{- with $v.kdc.extraKrb5Conf }}

{{ . }}
{{- end }}
{{- end }}

{{- define "krb5-rs-kdc.cockroachKdcConf" -}}
{{- $v := .Values }}
[kdcdefaults]
 kdc_ports = {{ $v.kdc.containerPort }}
 kdc_tcp_ports = {{ $v.kdc.containerPort }}

[realms]
 {{ required "realm is required" $v.realm }} = {
  database_module = crdb
  max_life = {{ $v.kdc.maxLife }}
  max_renewable_life = {{ $v.kdc.maxRenewableLife }}
  supported_enctypes = {{ $v.kdc.supportedEnctypes }}
 }
{{- with $v.kdc.extraKdcConf }}

{{ . }}
{{- end }}

{{ include "krb5-rs-kdc.cockroachDbmodule" (dict "ctx" . "url" $v.cockroach.url "certDir" "/crdb" "kdc" true) }}
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
