// main template for cert-exporter
local kap = import 'lib/kapitan.libjsonnet';
local kube = import 'lib/kube.libjsonnet';
local inv = kap.inventory();
// The hiera parameters for the component
local params = inv.parameters.cert_exporter;

local common = import 'common.libsonnet';

local namespace = kube.Namespace(params.namespace) {
  metadata+: {
    labels+: {
      'app.kubernetes.io/name': params.namespace,
      // Configure the namespaces so that the OCP4 cluster-monitoring
      // Prometheus can find the servicemonitors and rules.
      [if common.isOpenshift && params.openshift_cluster_monitoring then 'openshift.io/cluster-monitoring']: 'true',
    },
  },
};

// Define outputs below
{
  '00_namespace': namespace,
}
