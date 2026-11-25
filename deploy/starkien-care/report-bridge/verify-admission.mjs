import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";

const [context, namespace] = process.argv.slice(2);
if (process.argv.length !== 4 || !context || !/^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/.test(namespace)) {
  throw new Error("Usage: node verify-admission.mjs KUBE_CONTEXT TENANT_NAMESPACE");
}
function kubectl(args, resource) {
  const result = spawnSync("kubectl", ["--context", context, "--namespace", namespace, ...args], {
    encoding: "utf8", timeout: 20_000, input: resource && JSON.stringify(resource),
  });
  if (result.error) throw result.error;
  return result;
}
function checked(args, resource) {
  const result = kubectl(args, resource);
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}
const tenant = checked(["get", "namespace", namespace, "-o", "json"]);
assert.equal(tenant.metadata.labels["care.starkien.com/report-runtime"], "true");
const guard = checked(["get", "networkpolicy", "care-connect-report-default-deny", "-o", "json"]);
assert.deepEqual(guard.spec.podSelector, {});
assert.ok(guard.spec.policyTypes.includes("Egress") && !(guard.spec.egress?.length));
const suffix = randomUUID().replaceAll("-", "").slice(0, 12);
const metadata = { namespace, name: "allow-agent-runtime-" + suffix };
const broad = {
  apiVersion: "networking.k8s.io/v1", kind: "NetworkPolicy", metadata,
  spec: { podSelector: {}, policyTypes: ["Egress"], egress: [
    { to: [{ ipBlock: { cidr: "0.0.0.0/0" } }], ports: [{ protocol: "TCP", port: 443 }] },
  ] },
};
const dryRun = ["create", "--dry-run=server", "-f", "-", "-o", "json"];
const rendered = checked(dryRun, broad);
assert.deepEqual(rendered.spec.egress, [{
  ports: [{ protocol: "TCP", port: 8443 }],
  to: [{
    namespaceSelector: { matchLabels: { "kubernetes.io/metadata.name": "care-connect" } },
    podSelector: { matchLabels: { "app.kubernetes.io/name": "care-connect-relay" } },
  }],
}]);
const unexpected = { ...broad, metadata: { ...metadata, name: "unexpected-" + suffix } };
const refused = kubectl(dryRun, unexpected);
assert.notEqual(refused.status, 0);
assert.match(refused.stderr, /Care Connect permits only the private model relay/);
const pod = checked(dryRun, {
  apiVersion: "v1", kind: "Pod", metadata: {
    namespace, name: "care-report-probe-" + suffix, labels: { "openclaw.dev/workload-role": "gateway" },
  },
  spec: {
    securityContext: { runAsNonRoot: true, seccompProfile: { type: "RuntimeDefault" } },
    containers: [{
      name: "gateway", image: "unused.invalid/dry-run",
      securityContext: { allowPrivilegeEscalation: false, capabilities: { drop: ["ALL"] } },
    }],
    volumes: [{ name: "openclaw-service-principal", projected: {
      sources: [{ serviceAccountToken: { audience: "care-connect-report", path: "token", expirationSeconds: 900 } }],
    } }],
  },
});
const mount = pod.spec.containers.find(c => c.name === "gateway").volumeMounts
  .find(v => v.name === "care-connect-report-trust");
assert.equal(mount.mountPath, "/var/run/secrets/care-connect");
assert.equal(mount.readOnly, true);
assert.equal(pod.spec.volumes.find(v => v.name === mount.name).configMap.name, mount.name);
console.log("Private peer, additive policy denial and gateway trust projection passed API admission.");
