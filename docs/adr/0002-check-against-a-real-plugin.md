# 2. Check against a real plugin, not just the documentation

Status: accepted

## Context

The evaluator's unit tests are anchored to the Kubernetes documentation: its example policy and
the behaviour it states for it, its contrast between one peer with two selectors and two
peers, and its default-policy recipes. That checks netpolwarden against the documentation's
words. It does not check it against what a cluster does.

## Decision

`scripts/differential.sh` creates a kind cluster with Calico, applies a fixture of pods that
run agnhost and policies that cover the hard cases (AND against OR, named ports that exist and
do not, egress isolation, cross-namespace selectors, a default deny), and tries every pod to
pod connection on every declared port with `agnhost connect`. For each one, `netpolwarden
--can` must give the same answer. It runs in CI. The machine this was written on keeps
Docker's storage off limits, so the first run of the check is the first CI run.

## Consequences

- Calico is one implementation. Where plugins disagree with each other (ipBlock and pod
  addresses, the timing of policy application), this check cannot speak for the others, and
  the fixture avoids those areas.
- A failure in this job is either a bug in netpolwarden or a place where the documentation and
  a real plugin part ways. Either is worth knowing, and the README will say which it was.
