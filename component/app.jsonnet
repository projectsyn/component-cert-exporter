local kap = import 'lib/kapitan.libjsonnet';
local inv = kap.inventory();
local params = inv.parameters.cert_exporter;
local argocd = import 'lib/argocd.libjsonnet';

local app = argocd.App('cert-exporter', params.namespace);

{
  'cert-exporter': app,
}
