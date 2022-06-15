local com = import 'lib/commodore.libjsonnet';
local kap = import 'lib/kapitan.libjsonnet';
local kube = import 'lib/kube.libjsonnet';
local inv = kap.inventory();
local params = inv.parameters.cert_exporter;

local isOpenshift = std.startsWith(inv.parameters.facts.distribution, 'openshift');

assert
  std.member(inv.applications, 'rancher-monitoring') ||
  std.member(inv.applications, 'openshift4-monitoring')
  : 'Neither rancher-monitoring nor openshift4-monitoring is available';

// Upstream alerts to ignore
local ignore_alerts = std.set(
  // Add set of alerts that should be ignored from `params.alerts`
  com.renderArray(params.alerts.ignoreNames)
);

/* FROM HERE: should be provided as library function by
 * rancher-/openshift4-monitoring */
// We shouldn't be expected to care how rancher-/openshift4-monitoring
// implement alert managmement and patching, instead we should be able to
// reuse their functionality as a black box to make sure our alerts work
// correctly in the environment into which we're deploying.

local global_alert_params =
  if isOpenshift then
    inv.parameters.openshift4_monitoring.alerts
  else
    inv.parameters.rancher_monitoring.alerts;

local filter_patch_rules(g) =
  // combine our set of alerts to ignore with the monitoring component's
  // set of ignoreNames.
  local ignore_set = std.set(global_alert_params.ignoreNames + ignore_alerts);
  g {
    local filtered_rules = std.filter(
      // Filter out unwanted rules
      function(rule)
        // Drop rules which are in the ignore_set
        !std.member(ignore_set, rule.alert),
      super.rules
    ),
    rules: std.map(
      function(rule) rule + com.makeMergeable(
        com.getValueOrDefault(
          params.alerts.patchRules,
          rule.alert,
          {}
        )
      ),
      filtered_rules
    ),
  };

/* TO HERE */

local alertrules = {
  groups: [
    {
      name: 'cert-exporter-alert.rules',
      rules: [
        {
          alert: 'SYN_X509ExporterReadErrors',
          annotations: {
            description: |||
              Over the last 15 minutes, this x509-certificate-exporter
              instance has experienced errors reading certificate files or querying
              the Kubernetes API. This could be caused by a misconfiguration if triggered
              when the exporter starts.
            |||,
            message: 'Increasing read errors for x509-certificate-exporter',
            runbook_url: 'https://hub.syn.tools/cert-exporter/runbooks/X509ExporterReadErrors.html',
            severity_level: 'warning',
          },
          expr: 'delta(x509_read_errors[15m]) > 0',
          'for': '5m',
          labels: {
            severity: 'warning',
            syn: 'true',
            syn_component: 'cert-exporter',
          },
        },
        {
          alert: 'SYN_CertificateError',
          annotations: {
            description: |||
              Certificate at location {{ $labels.filepath }} in Kubernetes secret
              {{ $labels.secret_name }} in namespace {{ $labels.secret_namespace }}
              couldn't be decoded.
            |||,
            message: 'Certificate cannot be decoded',
            runbook_url: 'https://hub.syn.tools/cert-exporter/runbooks/CertificateError.html',
            severity_level: 'critical',
          },
          expr: 'x509_cert_error > 0',
          'for': '5m',
          labels: {
            severity: 'critical',
            syn: 'true',
            syn_component: 'cert-exporter',
          },
        },
        {
          alert: 'SYN_CertificateRenewal',
          annotations: {
            description: |||
              Certificate for {{ $labels.subject_CN }} in Kubernetes secret
              {{ $labels.secret_name }} in namespace {{ $labels.secret_namespace }}
              should be renewed.
            |||,
            message: 'Certificate should be renewed',
            runbook_url: 'https://hub.syn.tools/cert-exporter/runbooks/CertificateRenewal.html',
            severity_level: 'warning',
          },
          expr: '((x509_cert_not_after - time()) / 86400) < 28',
          'for': '15m',
          labels: {
            severity: 'warning',
            syn: 'true',
            syn_component: 'cert-exporter',
          },
        },
        {
          alert: 'SYN_CertificateExpiration',
          annotations: {
            description: |||
              Certificate for {{ $labels.subject_CN }} in Kubernetes secret
              {{ $labels.secret_name }} in namespace {{ $labels.secret_namespace }}
              is about to expire.
            |||,
            message: 'Certificate is about to expire',
            runbook_url: 'https://hub.syn.tools/cert-exporter/runbooks/CertificateExpiration.html',
            severity_level: 'critical',
          },
          expr: '((x509_cert_not_after - time()) / 86400) < 14',
          'for': '15m',
          labels: {
            severity: 'critical',
            syn: 'true',
            syn_component: 'cert-exporter',
          },
        },
      ],
    },
  ],
};

{
  '20_rules': kube._Object('monitoring.coreos.com/v1', 'PrometheusRule', 'syn-cert-exporter-rules') {
    metadata+: {
      namespace: params.namespace,
    },
    spec: {
      groups: std.filter(
        function(it) it != null,
        [
          local r = filter_patch_rules(g);
          if std.length(r.rules) > 0 then r
          for g in alertrules.groups
        ]
      ),
    },
  },
}
