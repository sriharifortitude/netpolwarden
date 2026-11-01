package k8s

import (
	"strings"
	"testing"
)

func read(t *testing.T, yaml string) *Cluster {
	t.Helper()
	c := New()
	if err := c.Read("t.yaml", []byte(yaml), "default"); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestEveryWorkloadKindGivesItsPodLabels(t *testing.T) {
	c := read(t, `
apiVersion: apps/v1
kind: Deployment
metadata: {name: d, namespace: a, labels: {ignored: yes}}
spec:
  template:
    metadata: {labels: {app: d}}
    spec:
      containers:
        - name: c
          ports: [{name: http, containerPort: 8080}, {containerPort: 53, protocol: udp}]
---
apiVersion: batch/v1
kind: CronJob
metadata: {name: cj}
spec:
  jobTemplate:
    spec:
      template:
        metadata: {labels: {app: cj}}
        spec: {containers: [{name: c}]}
---
apiVersion: v1
kind: List
items:
  - apiVersion: apps/v1
    kind: StatefulSet
    metadata: {name: s, namespace: b}
    spec: {template: {metadata: {labels: {app: s}}, spec: {containers: [{name: c}]}}}
  - apiVersion: v1
    kind: Pod
    metadata: {name: p, namespace: b, labels: {app: p}}
    spec: {containers: [{name: c}]}
  - apiVersion: v1
    kind: ConfigMap
    metadata: {name: ignored}
`)
	want := map[string]string{"a/Deployment/d": "d", "default/CronJob/cj": "cj", "b/StatefulSet/s": "s", "b/Pod/p": "p"}
	if len(c.Workloads) != len(want) {
		t.Fatalf("%+v", c.Workloads)
	}
	for _, w := range c.Workloads {
		if want[w.ID()] != w.Labels["app"] {
			t.Errorf("%s: labels %v", w.ID(), w.Labels)
		}
	}
	d := c.Workloads[0]
	if len(d.Ports) != 2 || d.Ports[0].Protocol != "TCP" || d.Ports[1].Protocol != "UDP" || d.Ports[0].Name != "http" {
		t.Fatalf("%+v", d.Ports)
	}
}

func TestNamespacesGetTheirNameLabel(t *testing.T) {
	c := read(t, "apiVersion: v1\nkind: Namespace\nmetadata: {name: shop, labels: {team: x}}\n---\n"+
		"apiVersion: v1\nkind: Pod\nmetadata: {name: p, namespace: other}\nspec: {containers: [{name: c}]}\n")
	shop, other := c.Namespaces["shop"], c.Namespaces["other"]
	if shop.Labels[NameLabel] != "shop" || shop.Labels["team"] != "x" || !shop.Declared {
		t.Fatalf("%+v", shop)
	}
	if other.Labels[NameLabel] != "other" || other.Declared {
		t.Fatalf("a namespace only referred to: %+v", other)
	}
}

func TestTheNameLabelCannotBeForged(t *testing.T) {
	c := read(t, "apiVersion: v1\nkind: Namespace\nmetadata: {name: shop, labels: {kubernetes.io/metadata.name: kube-system}}\n")
	if c.Namespaces["shop"].Labels[NameLabel] != "shop" {
		t.Fatalf("the API server sets the name label to the real name: %v", c.Namespaces["shop"].Labels)
	}
	if len(c.Problems) != 1 || !strings.Contains(c.Problems[0], "replaces it") {
		t.Fatalf("%v", c.Problems)
	}
}

func TestANullSectionIsAbsent(t *testing.T) {
	c := read(t, `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: a}
spec:
  podSelector: {}
  egress: null
  ingress: ~
`)
	p := c.Policies[0]
	if p.EgressType || !p.IngressType || p.Egress != nil || p.Ingress != nil {
		t.Fatalf("egress: null is no egress section, so the policy is ingress-only: %+v", p)
	}
}

func TestPolicyTypesAndRuleShapes(t *testing.T) {
	c := read(t, `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: a}
spec:
  podSelector: {}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: b}
spec:
  podSelector: {}
  egress: []
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: c}
spec:
  podSelector: {}
  policyTypes: [Egress]
  ingress:
    - {}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: d}
spec:
  podSelector: {}
  policyTypes: [Sideways]
`)
	p := map[string]Policy{}
	for _, x := range c.Policies {
		p[x.Name] = x
	}
	if !p["a"].IngressType || p["a"].EgressType || p["a"].Ingress != nil {
		t.Fatalf("a: %+v", p["a"])
	}
	if !p["b"].EgressType || p["b"].Egress == nil || len(p["b"].Egress) != 0 {
		t.Fatalf("b: an empty egress list still makes the policy an egress policy: %+v", p["b"])
	}
	if p["c"].IngressType || !p["c"].EgressType || len(p["c"].Ingress) != 1 || p["c"].Ingress[0].Line == 0 {
		t.Fatalf("c: %+v", p["c"])
	}
	if len(c.Problems) != 1 || !strings.Contains(c.Problems[0], "Sideways") {
		t.Fatalf("%v", c.Problems)
	}
}

func TestPorts(t *testing.T) {
	c := read(t, `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: a}
spec:
  podSelector: {}
  ingress:
    - ports: [{port: 80}, {port: http, protocol: udp}, {protocol: TCP}, {port: 1000, endPort: 2000}]
`)
	ps := c.Policies[0].Ingress[0].Ports
	if ps[0].Number() != 80 || ps[0].Proto() != "TCP" || ps[0].Name() != "" {
		t.Fatalf("%+v", ps[0])
	}
	if ps[1].Name() != "http" || ps[1].Number() != 0 || ps[1].Proto() != "UDP" {
		t.Fatalf("%+v", ps[1])
	}
	if ps[2].Name() != "" || ps[2].Number() != 0 || ps[2].Port.Kind != 0 {
		t.Fatalf("%+v", ps[2])
	}
	if *ps[3].EndPort != 2000 {
		t.Fatal("endPort")
	}
}

func TestBrokenYAML(t *testing.T) {
	if err := New().Read("t.yaml", []byte("kind: Pod\n  bad: [indent\n"), "default"); err == nil {
		t.Fatal("want an error")
	}
	c := read(t, "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata: {name: x}\nspec:\n  podSelector: {}\n  ingress: {not: a list}\n")
	if len(c.Problems) != 1 || len(c.Policies) != 0 {
		t.Fatalf("%v %v", c.Problems, c.Policies)
	}
}

func FuzzRead(f *testing.F) {
	f.Add("kind: NetworkPolicy\nmetadata: {name: x}\nspec: {podSelector: {}, ingress: [{}]}\n")
	f.Add("kind: List\nitems: [{kind: Pod, metadata: {name: p}}]\n")
	f.Fuzz(func(t *testing.T, s string) {
		_ = New().Read("f", []byte(s), "default")
	})
}
