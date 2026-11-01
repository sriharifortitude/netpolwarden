# netpolwarden

[![CI](https://github.com/sriharifortitude/netpolwarden/actions/workflows/ci.yml/badge.svg)](https://github.com/sriharifortitude/netpolwarden/actions/workflows/ci.yml)

Works out who can reach whom under Kubernetes NetworkPolicies, from manifests, and finds the
policies that do not do what they look like they do: a label typo that selects nothing, two
peers where one was meant, a named port no pod declares, an egress lockdown that also blocks
DNS. Answers "can A reach B on port X?" with the policies that decide it. Go, MIT.

## What it is for

NetworkPolicy reads simply and behaves subtly. A pod is open to everything until some policy
selects it. Policies add up. A connection needs both the source's egress and the
destination's ingress. One dash of YAML indentation turns "pods labelled prometheus in the
monitoring namespace" into "every pod in monitoring, or anything labelled prometheus here".
None of this shows in `kubectl apply`:

<!-- demo:start -->
```
$ netpolwarden testdata/shop.yaml
NP006 medium   NetworkPolicy shop/api-from-frontend ingress allows the named port "metrics" (TCP), but no pod this policy selects declares a port with that name: the rule lets nothing in  (testdata/shop.yaml:145)
NP001 medium   namespace ingress-nginx has no NetworkPolicy: its workload accepts connections from every pod in the cluster and from outside it
NP001 medium   namespace legacy has no NetworkPolicy: its workload accepts connections from every pod in the cluster and from outside it
NP001 medium   namespace monitoring has no NetworkPolicy: its workload accepts connections from every pod in the cluster and from outside it
NP005 medium   workload shop/StatefulSet/db is egress-isolated and no egress rule allows port 53: its DNS lookups will fail, so it cannot reach services by name  (testdata/shop.yaml:62)
NP002 low      NetworkPolicy shop/api-from-frontend an ingress podSelector matches no workload in shop: check the labels  (testdata/shop.yaml:145)
NP003 low      NetworkPolicy shop/api-from-frontend ingress lists a namespaceSelector and a podSelector as two separate peers, which means either one: every pod in the selected namespaces, or matching pods in this namespace. If the intent was matching pods in those namespaces, both selectors belong in one list item (one '-')  (testdata/shop.yaml:145)
NP002 low      NetworkPolicy shop/payments-egress selects no workload in namespace shop: check the podSelector labels  (testdata/shop.yaml:163)
7 workload(s), 6 NetworkPolicy(ies) in 4 namespace(s); 5 medium, 3 low

$ netpolwarden testdata/shop.yaml --can "monitoring/prometheus shop/api 9100"
DENIED   monitoring/Deployment/prometheus -> shop/Deployment/api on 9100/TCP
  Egress: open, no policy selects monitoring/Deployment/prometheus for egress
  Ingress: denied, shop/Deployment/api is isolated and no rule matches

$ netpolwarden testdata/shop.yaml --matrix
ingress-nginx/Deployment/controller 80/TCP (http) <- legacy/Deployment/reports, monitoring/Deployment/prometheus, shop/CronJob/payments-sync, shop/Deployment/api, shop/Deployment/frontend, and outside the cluster
legacy/Deployment/reports 8080/TCP (http) <- ingress-nginx/Deployment/controller, monitoring/Deployment/prometheus, shop/CronJob/payments-sync, shop/Deployment/api, shop/Deployment/frontend, and outside the cluster
monitoring/Deployment/prometheus 9090/TCP (web) <- ingress-nginx/Deployment/controller, legacy/Deployment/reports, shop/CronJob/payments-sync, shop/Deployment/api, shop/Deployment/frontend, and outside the cluster
shop/CronJob/payments-sync 80/TCP (declares no ports; 80 tested) <- nothing
shop/Deployment/api 9000/TCP (http) <- shop/Deployment/frontend
shop/Deployment/api 9100/TCP (prom) <- nothing
shop/Deployment/frontend 8080/TCP (http) <- ingress-nginx/Deployment/controller
shop/StatefulSet/db 5432/TCP (postgres) <- shop/Deployment/api
```
<!-- demo:end -->

The first query shows the cost of two mistakes in one rule (testdata/shop.yaml, line 145):
Prometheus was meant to scrape the API, but the rule names a port called `metrics` that the
API declares as `prom`, and the selectors it uses are written as two peers. In the matrix,
the ingress controller can be reached by everything except the database: the database's
egress lockdown also stops it calling the controller, and it blocks the database's own DNS.

## Usage

```bash
go install github.com/sriharifortitude/netpolwarden/cmd/netpolwarden@v0.1.0

netpolwarden manifests/                               # findings
netpolwarden manifests/ --can "shop/frontend shop/db 5432"
netpolwarden manifests/ --matrix                      # every workload, every port, who gets in
kubectl get ns,deploy,sts,ds,netpol -A -o yaml | netpolwarden -
```

The manifests must be the whole picture: a policy left out is a policy not counted. `--can`
takes `namespace/name` or `namespace/Kind/name` for each end, or `outside`, and a port with an
optional protocol (`5432`, `53/UDP`); it exits 0 when the connection is allowed and 1 when it is
not. Otherwise exit codes are 0 nothing at or above `--fail-on` (default medium), 1 a finding
is, 2 a usage error or unreadable input.

## Checks

| ID | Severity | What it finds |
|---|---|---|
| NP001 | medium | a namespace with no NetworkPolicy, or workloads in a namespace that no policy selects: open to every pod and to outside |
| NP002 | low | a policy, podSelector or namespaceSelector that matches nothing in the manifests: usually a label typo |
| NP003 | low | a rule that lists a namespaceSelector and a podSelector as two peers (OR) where one peer with both (AND) is a common intent |
| NP004 | low | ingress from every namespace (`namespaceSelector: {}`) or from `0.0.0.0/0` |
| NP005 | medium | an egress-isolated workload that no rule lets reach port 53: DNS fails |
| NP006 | medium | an ingress rule naming a port that no selected pod declares: the rule lets nothing in |
| NP007 | medium | ingress or egress rules that policyTypes leaves out, which the API ignores |
| NP008 | info | a policy that denies all ingress and all egress |
| NP010 | high | specs the API rejects: an unknown selector operator, values on Exists, endPort without a port, a peer with both or neither of ipBlock and selectors, an invalid CIDR or except, an unknown protocol |

## How it evaluates

As the API defines it, not as one plugin implements it. [ADR 1](docs/adr/0001-the-whole-picture-or-nothing.md)
lists the rules. The cases people get wrong: an egress section without policyTypes makes the
policy an egress policy too; `ingress: []` and no ingress at all both deny everything;
`ingress: [{}]` allows everything; a podSelector without a namespaceSelector means the
policy's own namespace; named ports resolve on the destination pod, protocol included. An
`ipBlock` is taken to mean traffic from or to outside the cluster, because plugins disagree on
whether pod addresses inside its range match.

## Tested

```bash
go test ./...                       # 33 tests and a fuzz target
./scripts/differential.sh           # against Calico on a kind cluster; needs docker, kind, kubectl
```

The evaluator's tests are anchored to the Kubernetes documentation, not to my reading of it.
They use the documentation's example policy and the behaviour it states for it (which pods
in which namespaces reach the database, and on which port), its side-by-side contrast between
one peer with two selectors and two peers, and its default-policy recipes. All of them pass.

**Against a real plugin: written, not yet run.** `scripts/differential.sh` creates a kind
cluster with Calico 3.28, applies `testdata/differential/cluster.yaml` (five agnhost pods in
two namespaces, and policies for AND against OR, named ports that exist and do not, egress
isolation, cross-namespace selectors and a default deny), opens a real TCP connection for
every pair of pods on every declared port, and requires `netpolwarden --can` to give the same
answer for each. Docker's storage on the machine this was built on is off limits, so this runs
for the first time in CI. Until it passes there, treat the evaluator as agreeing with the
documentation, not yet with a cluster. [ADR 2](docs/adr/0002-check-against-a-real-plugin.md).

**Mutation testing.** I broke the code in 50 places on purpose. On the first run, 12 mutants survived and 2 did not compile; I rewrote those so they do, and two of the survivors changed nothing a caller can observe, so I dropped them. The rest found one bug and several gaps. The bug: a policy with `ingress: []` and `egress: []` was not reported as denying everything, because the check looked for a missing section rather than an empty one, though the API treats the two alike. The gaps: no test separated a missing label from a label with an empty value (in matchLabels, In, NotIn and Exists); none used a named port with the other protocol; none let DNS through a port range, or through a rule with no ports, when the DNS server is not in the manifests; none had a podSelector that matched only in another namespace; and none checked the matrix's "every workload, and outside the cluster" line. Each now has a test. All 48 remaining mutants are caught, and the deny-all test also catches the old bug when it is put back.

**Not tested:** other plugins (Cilium, Antrea, OVN-Kubernetes), whose edge cases differ;
`ipBlock` against pod addresses; AdminNetworkPolicy and plugin-specific policy kinds
(CiliumNetworkPolicy, Calico's GlobalNetworkPolicy), which are not read at all; Services,
which NetworkPolicy does not consider (traffic is judged pod to pod).

## Limits

- **Manifests, not a cluster.** Labels added at runtime, pods without a manifest and policies
  applied by other tools are invisible.
- **Workloads stand in for pods.** Every pod of a Deployment is assumed to have its template's
  labels and ports.
- **Ports a pod does not declare** are not probed in the matrix; `--can` answers for any port.
  A pod can listen on a port it does not declare, and NetworkPolicy allows numeric ports
  whether or not they are declared.

## Licence

MIT.
