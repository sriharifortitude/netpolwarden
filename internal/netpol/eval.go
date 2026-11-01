// Package netpol evaluates Kubernetes NetworkPolicies (networking.k8s.io/v1) the way the API
// defines them: a pod is open until a policy selects it; once selected, only what some selecting
// policy's rules allow gets through; and a connection needs both the source's egress and the
// destination's ingress to allow it.
package netpol

import (
	"fmt"
	"sort"
	"strings"

	"github.com/sriharifortitude/netpolwarden/internal/k8s"
)

// Matches reports whether labels satisfy a selector. An empty selector matches everything. An
// unknown operator matches nothing (the API rejects it; Check reports it).
func Matches(sel k8s.Selector, labels map[string]string) bool {
	for k, v := range sel.MatchLabels {
		if got, ok := labels[k]; !ok || got != v {
			return false
		}
	}
	for _, r := range sel.MatchExpressions {
		got, has := labels[r.Key]
		switch r.Operator {
		case "In":
			if !has || !contains(r.Values, got) {
				return false
			}
		case "NotIn":
			if has && contains(r.Values, got) {
				return false
			}
		case "Exists":
			if !has {
				return false
			}
		case "DoesNotExist":
			if has {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// Endpoint is one end of a connection: a workload, or a place outside the cluster.
type Endpoint struct {
	Workload *k8s.Workload
	// External is set for traffic from or to outside the cluster.
	External bool
}

func (e Endpoint) String() string {
	if e.External {
		return "outside the cluster"
	}
	return e.Workload.ID()
}

// Verdict is the answer for one connection, with the policies that decided each side.
type Verdict struct {
	Allowed bool
	// EgressIsolated and IngressIsolated say whether each side is restricted at all.
	EgressIsolated, IngressIsolated bool
	EgressAllowed, IngressAllowed   bool
	// EgressBy and IngressBy name the policies whose rules allowed the traffic.
	EgressBy, IngressBy []string
}

// Analyzer answers reachability questions about one cluster.
type Analyzer struct {
	C *k8s.Cluster
}

func (a Analyzer) nsLabels(ns string) map[string]string {
	if n, ok := a.C.Namespaces[ns]; ok {
		return n.Labels
	}
	return map[string]string{k8s.NameLabel: ns}
}

// Selecting returns the policies that select a workload, in its namespace.
func (a Analyzer) Selecting(w *k8s.Workload) []*k8s.Policy {
	var out []*k8s.Policy
	for i := range a.C.Policies {
		p := &a.C.Policies[i]
		if p.Namespace == w.Namespace && Matches(p.PodSelector, w.Labels) {
			out = append(out, p)
		}
	}
	return out
}

// IngressIsolated reports whether any policy restricts traffic into a workload.
func (a Analyzer) IngressIsolated(w *k8s.Workload) bool {
	for _, p := range a.Selecting(w) {
		if p.IngressType {
			return true
		}
	}
	return false
}

// EgressIsolated reports whether any policy restricts traffic out of a workload.
func (a Analyzer) EgressIsolated(w *k8s.Workload) bool {
	for _, p := range a.Selecting(w) {
		if p.EgressType {
			return true
		}
	}
	return false
}

// peerMatches reports whether a rule's peer covers an endpoint. policyNS is the namespace of the
// policy, which a podSelector without a namespaceSelector refers to. An ipBlock covers only
// traffic from outside the cluster; how a plugin treats pod addresses inside an ipBlock varies.
func (a Analyzer) peerMatches(peer k8s.Peer, e Endpoint, policyNS string) bool {
	if peer.IPBlock != nil {
		return e.External
	}
	if e.External {
		return false
	}
	w := e.Workload
	switch {
	case peer.NamespaceSelector != nil && peer.PodSelector != nil:
		return Matches(*peer.NamespaceSelector, a.nsLabels(w.Namespace)) && Matches(*peer.PodSelector, w.Labels)
	case peer.NamespaceSelector != nil:
		return Matches(*peer.NamespaceSelector, a.nsLabels(w.Namespace))
	case peer.PodSelector != nil:
		return w.Namespace == policyNS && Matches(*peer.PodSelector, w.Labels)
	}
	return false
}

// portMatches reports whether a rule's port entry covers port/proto on the destination. A named
// port is looked up among the destination's container ports.
func portMatches(p k8s.Port, port int, proto string, dst Endpoint) bool {
	if p.Proto() != proto {
		return false
	}
	if name := p.Name(); name != "" {
		if dst.External {
			return false
		}
		for _, cp := range dst.Workload.Ports {
			if cp.Name == name && cp.Protocol == proto && cp.Port == port {
				return true
			}
		}
		return false
	}
	n := p.Number()
	if n == 0 && p.Port.Kind == 0 {
		return true // protocol only: every port
	}
	if p.EndPort != nil {
		return port >= n && port <= *p.EndPort
	}
	return port == n
}

func (a Analyzer) ruleAllows(r k8s.Rule, peers []k8s.Peer, peer Endpoint, port int, proto string, dst Endpoint, ns string) bool {
	if len(peers) > 0 {
		hit := false
		for _, p := range peers {
			if a.peerMatches(p, peer, ns) {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	if len(r.Ports) == 0 {
		return true
	}
	for _, p := range r.Ports {
		if portMatches(p, port, proto, dst) {
			return true
		}
	}
	return false
}

// Allowed works out whether src can open a connection to dst on port/proto.
func (a Analyzer) Allowed(src, dst Endpoint, port int, proto string) Verdict {
	v := Verdict{EgressAllowed: true, IngressAllowed: true}
	if !src.External {
		v.EgressIsolated = a.EgressIsolated(src.Workload)
		if v.EgressIsolated {
			v.EgressAllowed = false
			for _, p := range a.Selecting(src.Workload) {
				if !p.EgressType {
					continue
				}
				for _, r := range p.Egress {
					if a.ruleAllows(r, r.To, dst, port, proto, dst, p.Namespace) {
						v.EgressAllowed = true
						v.EgressBy = appendNew(v.EgressBy, p.ID())
					}
				}
			}
		}
	}
	if !dst.External {
		v.IngressIsolated = a.IngressIsolated(dst.Workload)
		if v.IngressIsolated {
			v.IngressAllowed = false
			for _, p := range a.Selecting(dst.Workload) {
				if !p.IngressType {
					continue
				}
				for _, r := range p.Ingress {
					if a.ruleAllows(r, r.From, src, port, proto, dst, p.Namespace) {
						v.IngressAllowed = true
						v.IngressBy = appendNew(v.IngressBy, p.ID())
					}
				}
			}
		}
	}
	v.Allowed = v.EgressAllowed && v.IngressAllowed
	return v
}

func appendNew(xs []string, x string) []string {
	if contains(xs, x) {
		return xs
	}
	return append(xs, x)
}

// Explain turns a verdict into a sentence.
func Explain(src, dst Endpoint, port int, proto string, v Verdict) string {
	var b strings.Builder
	what := fmt.Sprintf("%s -> %s on %d/%s", src, dst, port, proto)
	if v.Allowed {
		fmt.Fprintf(&b, "ALLOWED  %s\n", what)
	} else {
		fmt.Fprintf(&b, "DENIED   %s\n", what)
	}
	side := func(name string, isolated, allowed bool, by []string, endpoint Endpoint) {
		switch {
		case endpoint.External:
			fmt.Fprintf(&b, "  %s: not governed by NetworkPolicy (outside the cluster)\n", name)
		case !isolated:
			fmt.Fprintf(&b, "  %s: open, no policy selects %s for %s\n", name, endpoint, strings.ToLower(name))
		case allowed:
			fmt.Fprintf(&b, "  %s: allowed by %s\n", name, strings.Join(by, ", "))
		default:
			fmt.Fprintf(&b, "  %s: denied, %s is isolated and no rule matches\n", name, endpoint)
		}
	}
	side("Egress", v.EgressIsolated, v.EgressAllowed, v.EgressBy, src)
	side("Ingress", v.IngressIsolated, v.IngressAllowed, v.IngressBy, dst)
	return b.String()
}

// Probe is a port to test a destination on.
type Probe struct {
	Port  int
	Proto string
	Name  string
}

// ProbesFor lists a workload's declared ports, or 80/TCP for one that declares none.
func ProbesFor(w *k8s.Workload) []Probe {
	var out []Probe
	for _, p := range w.Ports {
		out = append(out, Probe{p.Port, p.Protocol, p.Name})
	}
	if len(out) == 0 {
		out = []Probe{{80, "TCP", ""}}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	return out
}
