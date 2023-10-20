local kap = import 'lib/kapitan.libjsonnet';
local inv = kap.inventory();
local params = inv.parameters.cert_exporter;
local argocd = import 'lib/argocd.libjsonnet';

local app = argocd.App(inv.parameters._instance, params.namespace);

{
  [inv.parameters._instance]: app,
}
