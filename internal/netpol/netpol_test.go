package netpol

import (
	"strings"
	"testing"

	"github.com/sriharifortitude/netpolwarden/internal/k8s"
)

func load(t *testing.T, yaml string) Analyzer {
	t.Helper()
	c := k8s.New()
	if err := c.Read("t.yaml", []byte(yaml), "default"); err != nil {
		t.Fatal(err)
	}
	return Analyzer{C: c}
}

func ep(t *testing.T, a Analyzer, id string) Endpoint {
	t.Helper()
	if id == "outside" {
		return Endpoint{External: true}
	}
	for i := range a.C.Workloads {
		if a.C.Workloads[i].ID() == id {
			return Endpoint{Workload: &a.C.Workloads[i]}
		}
	}
	t.Fatalf("no workload %s", id)
	return Endpoint{}
}

func can(t *testing.T, a Analyzer, src, dst string, port int, proto string) bool {
	t.Helper()
	return a.Allowed(ep(t, a, src), ep(t, a, dst), port, proto).Allowed
}

func pod(ns, name, labels, ports string) string {
	return "apiVersion: v1\nkind: Pod\nmetadata: {name: " + name + ", namespace: " + ns + ", labels: " + labels + "}\n" +
		"spec:\n  containers:\n    - name: c\n      ports: " + ports + "\n---\n"
}

func namespace(name, labels string) string {
	return "apiVersion: v1\nkind: Namespace\nmetadata: {name: " + name + ", labels: " + labels + "}\n---\n"
}

func TestSelectors(t *testing.T) {
	labels := map[string]string{"app": "web", "tier": "front"}
	for _, c := range []struct {
		sel  k8s.Selector
		want bool
	}{
		{k8s.Selector{}, true},
		{k8s.Selector{MatchLabels: map[string]string{"app": "web"}}, true},
		{k8s.Selector{MatchLabels: map[string]string{"app": "db"}}, false},
		{k8s.Selector{MatchExpressions: []k8s.Requirement{{Key: "tier", Operator: "In", Values: []string{"front", "back"}}}}, true},
		{k8s.Selector{MatchExpressions: []k8s.Requirement{{Key: "tier", Operator: "NotIn", Values: []string{"front"}}}}, false},
		{k8s.Selector{MatchExpressions: []k8s.Requirement{{Key: "env", Operator: "NotIn", Values: []string{"prod"}}}}, true},
		{k8s.Selector{MatchExpressions: []k8s.Requirement{{Key: "env", Operator: "In", Values: []string{"prod"}}}}, false},
		{k8s.Selector{MatchExpressions: []k8s.Requirement{{Key: "app", Operator: "Exists"}}}, true},
		{k8s.Selector{MatchExpressions: []k8s.Requirement{{Key: "app", Operator: "DoesNotExist"}}}, false},
		{k8s.Selector{MatchExpressions: []k8s.Requirement{{Key: "env", Operator: "DoesNotExist"}}}, true},
		{k8s.Selector{MatchExpressions: []k8s.Requirement{{Key: "app", Operator: "Equals", Values: []string{"web"}}}}, false},
		// A missing key is not a key with an empty value.
		{k8s.Selector{MatchLabels: map[string]string{"env": ""}}, false},
		{k8s.Selector{MatchExpressions: []k8s.Requirement{{Key: "env", Operator: "In", Values: []string{""}}}}, false},
		{k8s.Selector{MatchExpressions: []k8s.Requirement{{Key: "env", Operator: "NotIn", Values: []string{""}}}}, true},
		{k8s.Selector{MatchExpressions: []k8s.Requirement{{Key: "env", Operator: "Exists"}}}, false},
	} {
		if got := Matches(c.sel, labels); got != c.want {
			t.Errorf("%+v: got %v", c.sel, got)
		}
	}
}

// The example policy from the Kubernetes documentation ("Network Policies", "The NetworkPolicy
// resource"), with the behaviour the documentation states for it.
const docsExample = `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: test-network-policy, namespace: default}
spec:
  podSelector:
    matchLabels: {role: db}
  policyTypes: [Ingress, Egress]
  ingress:
    - from:
        - ipBlock:
            cidr: 172.17.0.0/16
            except: [172.17.1.0/24]
        - namespaceSelector:
            matchLabels: {project: myproject}
        - podSelector:
            matchLabels: {role: frontend}
      ports:
        - {protocol: TCP, port: 6379}
  egress:
    - to:
        - ipBlock: {cidr: 10.0.0.0/24}
      ports:
        - {protocol: TCP, port: 5978}
`

func TestTheDocumentationExample(t *testing.T) {
	a := load(t, namespace("myproject", "{project: myproject}")+namespace("other", "{}")+
		pod("default", "db", "{role: db}", "[{containerPort: 6379}]")+
		pod("default", "frontend", "{role: frontend}", "[]")+
		pod("default", "backend", "{role: backend}", "[]")+
		pod("myproject", "anything", "{app: x}", "[]")+
		pod("other", "frontend", "{role: frontend}", "[]")+docsExample)
	cases := []struct {
		src, dst string
		port     int
		want     bool
	}{
		{"default/Pod/frontend", "default/Pod/db", 6379, true},   // "any pod in the default namespace with the label role=frontend"
		{"myproject/Pod/anything", "default/Pod/db", 6379, true}, // "any pod in a namespace with the label project=myproject"
		{"outside", "default/Pod/db", 6379, true},                // the ipBlock
		{"default/Pod/backend", "default/Pod/db", 6379, false},
		{"other/Pod/frontend", "default/Pod/db", 6379, false}, // the podSelector is namespace-local
		{"default/Pod/frontend", "default/Pod/db", 5432, false},
		{"default/Pod/db", "default/Pod/frontend", 80, false}, // egress isolated, only 10.0.0.0/24:5978
		{"default/Pod/db", "outside", 5978, true},
		{"default/Pod/frontend", "default/Pod/backend", 80, true}, // not selected: open
	}
	for _, c := range cases {
		if got := can(t, a, c.src, c.dst, c.port, "TCP"); got != c.want {
			t.Errorf("%s -> %s:%d: got %v want %v", c.src, c.dst, c.port, got, c.want)
		}
	}
}

// The documentation contrasts one peer with both selectors (AND) and two peers (OR).
func TestAndVersusOr(t *testing.T) {
	base := namespace("client", "{user: alice}") + namespace("other", "{user: bob}") +
		pod("client", "web", "{role: client}", "[]") + pod("client", "batch", "{role: batch}", "[]") +
		pod("other", "web", "{role: client}", "[]") + pod("default", "web", "{role: client}", "[]") +
		pod("default", "server", "{app: server}", "[]")
	and := `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: p, namespace: default}
spec:
  podSelector: {matchLabels: {app: server}}
  ingress:
    - from:
        - namespaceSelector: {matchLabels: {user: alice}}
          podSelector: {matchLabels: {role: client}}
`
	or := strings.Replace(and, "          podSelector:", "        - podSelector:", 1)
	a := load(t, base+and)
	o := load(t, base+or)
	for _, c := range []struct {
		src     string
		wantAnd bool
		wantOr  bool
	}{
		{"client/Pod/web", true, true},
		{"client/Pod/batch", false, true}, // every pod in alice's namespaces, under OR
		{"default/Pod/web", false, true},  // role=client in the policy's own namespace, under OR
		{"other/Pod/web", false, false},
	} {
		if got := can(t, a, c.src, "default/Pod/server", 80, "TCP"); got != c.wantAnd {
			t.Errorf("AND %s: %v", c.src, got)
		}
		if got := can(t, o, c.src, "default/Pod/server", 80, "TCP"); got != c.wantOr {
			t.Errorf("OR %s: %v", c.src, got)
		}
	}
}

func TestDefaultPolicyRecipes(t *testing.T) {
	pods := pod("default", "a", "{app: a}", "[]") + pod("default", "b", "{app: b}", "[]")
	policy := func(spec string) string {
		return "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata: {name: p, namespace: default}\nspec:\n" + spec + "\n---\n"
	}
	cases := []struct {
		name, spec string
		in, ex     bool // a->b, outside->b
	}{
		{"deny all ingress", "  podSelector: {}\n  policyTypes: [Ingress]", false, false},
		{"allow all ingress", "  podSelector: {}\n  ingress:\n    - {}\n  policyTypes: [Ingress]", true, true},
		{"deny all egress", "  podSelector: {}\n  policyTypes: [Egress]", false, true},
		{"allow all egress", "  podSelector: {}\n  egress:\n    - {}\n  policyTypes: [Egress]", true, true},
		{"empty ingress list", "  podSelector: {}\n  ingress: []", false, false},
	}
	for _, c := range cases {
		a := load(t, pods+policy(c.spec))
		if got := can(t, a, "default/Pod/a", "default/Pod/b", 80, "TCP"); got != c.in {
			t.Errorf("%s: a->b %v", c.name, got)
		}
		if got := can(t, a, "outside", "default/Pod/b", 80, "TCP"); got != c.ex {
			t.Errorf("%s: outside->b %v", c.name, got)
		}
	}
}

func TestPolicyTypesDefault(t *testing.T) {
	a := load(t, pod("default", "a", "{app: a}", "[]")+pod("default", "b", "{app: b}", "[]")+`
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: p, namespace: default}
spec:
  podSelector: {matchLabels: {app: a}}
  egress:
    - to: [{podSelector: {matchLabels: {app: b}}}]
`)
	w := ep(t, a, "default/Pod/a").Workload
	if !a.EgressIsolated(w) || !a.IngressIsolated(w) {
		t.Fatal("an egress section without policyTypes means Ingress and Egress")
	}
	if !can(t, a, "default/Pod/a", "default/Pod/b", 80, "TCP") || can(t, a, "default/Pod/b", "default/Pod/a", 80, "TCP") {
		t.Fatal("egress to b allowed; ingress to a denied")
	}
}

func TestPorts(t *testing.T) {
	a := load(t, pod("default", "srv", "{app: srv}", "[{name: http, containerPort: 8080}, {name: dns, containerPort: 53, protocol: UDP}]")+
		pod("default", "cli", "{app: cli}", "[]")+`
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: p, namespace: default}
spec:
  podSelector: {matchLabels: {app: srv}}
  ingress:
    - ports:
        - {port: http}
        - {port: dns, protocol: UDP}
        - {port: 30000, endPort: 30010}
        - {protocol: SCTP}
`)
	for _, c := range []struct {
		port  int
		proto string
		want  bool
	}{
		{8080, "TCP", true}, {8080, "UDP", false}, {53, "UDP", true}, {53, "TCP", false},
		{30000, "TCP", true}, {30010, "TCP", true}, {30011, "TCP", false}, {29999, "TCP", false},
		{9999, "SCTP", true}, {81, "TCP", false},
		{8080, "UDP", false}, // "http" is declared as TCP; a UDP rule for it would not cover 8080/UDP either
	} {
		if got := can(t, a, "default/Pod/cli", "default/Pod/srv", c.port, c.proto); got != c.want {
			t.Errorf("%d/%s: %v", c.port, c.proto, got)
		}
	}
}

func TestPoliciesAreAdditiveAndNamespaced(t *testing.T) {
	a := load(t, pod("default", "srv", "{app: srv}", "[]")+pod("default", "x", "{app: x}", "[]")+pod("default", "y", "{app: y}", "[]")+
		pod("other", "srv", "{app: srv}", "[]")+`
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: from-x, namespace: default}
spec:
  podSelector: {matchLabels: {app: srv}}
  ingress: [{from: [{podSelector: {matchLabels: {app: x}}}]}]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: from-y, namespace: default}
spec:
  podSelector: {matchLabels: {app: srv}}
  ingress: [{from: [{podSelector: {matchLabels: {app: y}}}]}]
`)
	v := a.Allowed(ep(t, a, "default/Pod/y"), ep(t, a, "default/Pod/srv"), 80, "TCP")
	if !can(t, a, "default/Pod/x", "default/Pod/srv", 80, "TCP") || !v.Allowed || v.IngressBy[0] != "default/from-y" {
		t.Fatalf("policies add up: %+v", v)
	}
	if a.IngressIsolated(ep(t, a, "other/Pod/srv").Workload) {
		t.Fatal("a policy selects only pods in its own namespace")
	}
}

func TestExplain(t *testing.T) {
	a := load(t, pod("default", "a", "{app: a}", "[]")+pod("default", "b", "{app: b}", "[]")+
		"apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata: {name: deny, namespace: default}\nspec:\n  podSelector: {}\n")
	src, dst := ep(t, a, "default/Pod/a"), ep(t, a, "default/Pod/b")
	s := Explain(src, dst, 80, "TCP", a.Allowed(src, dst, 80, "TCP"))
	if !strings.HasPrefix(s, "DENIED") || !strings.Contains(s, "Egress: open") || !strings.Contains(s, "is isolated and no rule matches") {
		t.Fatal(s)
	}
}

// --- findings -------------------------------------------------------------------------------

func ids(fs []Finding) map[string]int {
	m := map[string]int{}
	for _, f := range fs {
		m[f.ID]++
	}
	return m
}

func check(t *testing.T, yaml string) []Finding {
	t.Helper()
	return Check(load(t, yaml).C)
}

const np = "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata: {name: p, namespace: default}\nspec:\n"

func TestOpenWorkloads(t *testing.T) {
	fs := check(t, pod("default", "a", "{app: a}", "[]"))
	if ids(fs)["NP001"] != 1 || !strings.Contains(fs[0].Message, "has no NetworkPolicy") {
		t.Fatal(fs)
	}
	fs = check(t, pod("default", "a", "{app: a}", "[]")+pod("default", "b", "{app: b}", "[]")+np+"  podSelector: {matchLabels: {app: a}}\n")
	if ids(fs)["NP001"] != 1 || !strings.Contains(fs[0].Message, "Pod/b") || strings.Contains(fs[0].Message, "Pod/a") {
		t.Fatal(fs)
	}
	if fs := check(t, pod("default", "a", "{app: a}", "[]")+np+"  podSelector: {}\n"); ids(fs)["NP001"] != 0 {
		t.Fatal(fs)
	}
}

func TestSelectorsThatMatchNothing(t *testing.T) {
	fs := check(t, pod("default", "a", "{app: a}", "[]")+np+`  podSelector: {matchLabels: {app: typo}}
  ingress:
    - from:
        - podSelector: {matchLabels: {app: nobody}}
        - namespaceSelector: {matchLabels: {team: nowhere}}
`)
	if ids(fs)["NP002"] != 3 {
		t.Fatal(fs)
	}
}

func TestOrTrapAndWideOpenPeers(t *testing.T) {
	fs := check(t, pod("default", "a", "{app: a}", "[]")+np+`  podSelector: {}
  ingress:
    - from:
        - namespaceSelector: {}
        - podSelector: {matchLabels: {app: a}}
    - from:
        - ipBlock: {cidr: 0.0.0.0/0}
`)
	if ids(fs)["NP003"] != 1 || ids(fs)["NP004"] != 2 {
		t.Fatal(fs)
	}
	// Both selectors in one peer: no trap.
	if fs := check(t, pod("default", "a", "{app: a}", "[]")+np+`  podSelector: {}
  ingress:
    - from:
        - namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: default}}
          podSelector: {matchLabels: {app: a}}
`); ids(fs)["NP003"] != 0 {
		t.Fatal(fs)
	}
}

func TestANamedPortMeansItsDeclaredProtocol(t *testing.T) {
	a := load(t, pod("default", "srv", "{app: srv}", "[{name: http, containerPort: 8080}]")+pod("default", "cli", "{app: cli}", "[]")+np+
		"  podSelector: {matchLabels: {app: srv}}\n  ingress: [{ports: [{port: http, protocol: UDP}]}]\n")
	if can(t, a, "default/Pod/cli", "default/Pod/srv", 8080, "UDP") || can(t, a, "default/Pod/cli", "default/Pod/srv", 8080, "TCP") {
		t.Fatal("the pod's http port is TCP, so a UDP rule naming it covers nothing")
	}
	if fs := Check(a.C); ids(fs)["NP006"] != 1 {
		t.Fatal(fs)
	}
}

func TestDenyAllWithEmptyLists(t *testing.T) {
	fs := check(t, pod("default", "a", "{app: a}", "[]")+np+"  podSelector: {}\n  policyTypes: [Ingress, Egress]\n  ingress: []\n  egress: []\n")
	if ids(fs)["NP008"] != 1 {
		t.Fatal("ingress: [] denies all ingress just as no ingress section does:", fs)
	}
}

func TestAPodSelectorMatchingOnlyElsewhere(t *testing.T) {
	fs := check(t, namespace("other", "{team: x}")+pod("other", "api", "{app: api}", "[]")+pod("default", "a", "{app: a}", "[]")+np+
		"  podSelector: {}\n  ingress:\n    - from:\n        - podSelector: {matchLabels: {app: api}}\n")
	if ids(fs)["NP002"] != 1 {
		t.Fatal("app=api exists only in another namespace; a bare podSelector looks in its own:", fs)
	}
}

func TestDNS(t *testing.T) {
	base := pod("default", "a", "{app: a}", "[]")
	if fs := check(t, base+np+"  podSelector: {}\n  policyTypes: [Egress]\n"); ids(fs)["NP005"] != 1 {
		t.Fatal(fs)
	}
	for _, egress := range []string{
		"    - ports: [{port: 53, protocol: UDP}]",
		"    - to: [{namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: kube-system}}}]\n      ports: [{port: 53, protocol: UDP}]",
		"    - {}",
		"    - ports: [{port: 1, endPort: 1000}]",
		// The DNS server is not in the manifests, so these rules decide on their ports alone.
		"    - to: [{namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: kube-system}}}]\n      ports: [{port: 1, endPort: 1000, protocol: UDP}]",
		"    - to: [{namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: kube-system}}}]",
	} {
		if fs := check(t, base+np+"  podSelector: {}\n  policyTypes: [Egress]\n  egress:\n"+egress+"\n"); ids(fs)["NP005"] != 0 {
			t.Errorf("%s: %v", egress, fs)
		}
	}
}

func TestNamedPortsAndIgnoredSections(t *testing.T) {
	fs := check(t, pod("default", "a", "{app: a}", "[{name: web, containerPort: 80}]")+np+`  podSelector: {}
  policyTypes: [Egress]
  ingress:
    - ports: [{port: http}]
  egress:
    - {}
`)
	if ids(fs)["NP007"] != 1 || !strings.Contains(fs[0].Message+fs[1].Message, "policyTypes does not list Ingress") {
		t.Fatal(fs)
	}
	fs = check(t, pod("default", "a", "{app: a}", "[{name: web, containerPort: 80}]")+np+"  podSelector: {}\n  ingress:\n    - ports: [{port: http}, {port: web}]\n")
	if ids(fs)["NP006"] != 1 || !strings.Contains(fs[0].Message, `"http"`) {
		t.Fatal(fs)
	}
}

func TestSpecsTheAPIRejects(t *testing.T) {
	for _, spec := range []string{
		"  podSelector: {matchExpressions: [{key: a, operator: Equals, values: [x]}]}",
		"  podSelector: {matchExpressions: [{key: a, operator: In}]}",
		"  podSelector: {matchExpressions: [{key: a, operator: Exists, values: [x]}]}",
		"  podSelector: {}\n  ingress: [{ports: [{endPort: 90}]}]",
		"  podSelector: {}\n  ingress: [{ports: [{port: 100, endPort: 90}]}]",
		"  podSelector: {}\n  ingress: [{ports: [{port: 80, protocol: ICMP}]}]",
		"  podSelector: {}\n  ingress: [{from: [{ipBlock: {cidr: 10.0.0.0/8}, podSelector: {}}]}]",
		"  podSelector: {}\n  ingress: [{from: [{}]}]",
		"  podSelector: {}\n  ingress: [{from: [{ipBlock: {cidr: not-a-cidr}}]}]",
		"  podSelector: {}\n  ingress: [{from: [{ipBlock: {cidr: 10.0.0.0/8, except: [192.168.0.0/16]}}]}]",
	} {
		if fs := check(t, pod("default", "a", "{app: a}", "[]")+np+spec+"\n"); ids(fs)["NP010"] == 0 {
			t.Errorf("%s: %v", spec, fs)
		}
	}
}

func TestDenyAllIsNoted(t *testing.T) {
	fs := check(t, pod("default", "a", "{app: a}", "[]")+np+"  podSelector: {}\n  policyTypes: [Ingress, Egress]\n")
	if ids(fs)["NP008"] != 1 {
		t.Fatal(fs)
	}
}
