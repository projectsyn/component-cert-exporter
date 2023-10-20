// instance-specific security context constraint object for openshift
local kap = import 'lib/kapitan.libjsonnet';
local kube = import 'lib/kube.libjsonnet';
local inv = kap.inventory();
// The hiera parameters for the component
local params = inv.parameters.cert_exporter;

local isOpenshift = std.startsWith(inv.parameters.facts.distribution, 'openshift');

local openshiftScc = {
  apiVersion: 'security.openshift.io/v1',
  kind: 'SecurityContextConstraints',
  metadata: {
    name: '%s-scc' % inv.parameters._instance,
    namespace: params.namespace,
    labels: {
      'app.kubernetes.io/name': 'cert-exporter',
      'app.kubernetes.io/component': 'cert-exporter',
      'app.kubernetes.io/managed-by': 'syn',
    },
  },
  users: [
    'system:serviceaccount:%s:%s-x509-certificate-exporter' % [ params.namespace, inv.parameters._instance ],
  ],
  volumes: [
    'secret',
  ],
  allowHostDirVolumePlugin: false,
  allowHostIPC: false,
  allowHostNetwork: false,
  allowHostPID: false,
  allowHostPorts: false,
  allowPrivilegeEscalation: false,
  allowPrivilegedContainer: false,
  allowedCapabilities: null,
  allowedUnsafeSysctls: null,
  defaultAddCapabilities: null,
  fsGroup: {
    type: 'MustRunAs',
    ranges: [ { min: 1, max: 65535 } ],
  },
  priority: null,
  runAsUser: {
    type: 'MustRunAsNonRoot',
  },
  seLinuxContext: {
    type: 'RunAsAny',
  },
  seccompProfiles: [
    '*',
  ],
  supplementalGroups: {
    type: 'MustRunAs',
    ranges: [ { min: 1, max: 65535 } ],
  },
  readOnlyRootFilesystem: true,
  requiredDropCapabilities: [
    'ALL',
  ],
};

// Define outputs below
{
  [if isOpenshift then '10_openshift-scc']: openshiftScc,
}
