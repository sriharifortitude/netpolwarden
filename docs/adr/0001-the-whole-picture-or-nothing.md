# 1. The whole picture, or no answer

Status: accepted

## Context

A NetworkPolicy never says "this is allowed" on its own. Whether a pod can be reached depends
on every policy in its namespace (they add up), on the labels of every namespace (a
namespaceSelector reads them), and on every pod's labels and declared ports (named ports are
looked up on the destination). This portfolio's manifest scanner, kubeshield, declines to
answer reachability questions for that reason: from a partial set of files, any answer is a
guess.

## Decision

netpolwarden takes the whole set of manifests and treats it as the cluster: Namespaces,
workloads (Pods and the pod templates of Deployments, StatefulSets, DaemonSets, ReplicaSets,
Jobs and CronJobs), and NetworkPolicies, as written or as `kubectl get -o yaml` prints them. A
namespace that only appears as a reference gets the one label Kubernetes always gives it,
`kubernetes.io/metadata.name`, and nothing more.

It evaluates the API's rules, not a plugin's: a pod is open until some policy with that
direction selects it; policies add up; a connection needs the source's egress and the
destination's ingress; policyTypes defaults to Ingress, plus Egress when an egress section
exists; a peer with both selectors is AND, two peers are OR; a podSelector without a
namespaceSelector means the policy's own namespace; named ports resolve on the destination.

## Consequences

- The answer is only as good as the input. A policy left out is a policy not counted, and the
  README and the usage text say so.
- `ipBlock` is taken to mean traffic from or to outside the cluster. Plugins differ on whether
  pod addresses inside an ipBlock range match, so pod-to-pod answers ignore ipBlock, and the
  real-cluster check leaves ipBlock out of its fixture.
- Workloads stand in for their pods: identical labels and ports per template. A Deployment
  whose pods are relabelled after creation is not modelled.
