local kap = import 'lib/kapitan.libjsonnet';
local inv = kap.inventory();
local params = inv.parameters.cert_exporter;

local isOpenshift = std.member([ 'openshift4', 'oke' ], inv.parameters.facts.distribution);

{
  isOpenshift: isOpenshift,
}
