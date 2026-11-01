package netpol

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/sriharifortitude/netpolwarden/internal/k8s"
)

// Severities, most serious first.
var Severities = []string{"critical", "high", "medium", "low", "info"}

// Rank orders severities: critical is 0.
func Rank(s string) int {
	for i, v := range Severities {
		if v == s {
			return i
		}
	}
	return len(Severities)
}

// Finding is one problem.
type Finding struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	// Where is a file and line, or empty for a finding about a namespace or workload.
	Where string `json:"where,omitempty"`
	// Object is the policy, workload or namespace concerned.
	Object  string `json:"object"`
	Message string `json:"message"`
}

// Check reports what the policies leave open, what they get wrong, and what the API rejects.
func Check(c *k8s.Cluster) []Finding {
	a := Analyzer{C: c}
	var out []Finding
	add := func(id, sev, where, obj, format string, args ...any) {
		out = append(out, Finding{ID: id, Severity: sev, Where: where, Object: obj, Message: fmt.Sprintf(format, args...)})
	}
	for _, p := range c.Problems {
		add("NP090", "info", "", "input", "%s", p)
	}

	// Open workloads.
	policiesIn := map[string]int{}
	for _, p := range c.Policies {
		policiesIn[p.Namespace]++
	}
	for _, ns := range c.SortedNamespaces() {
		var open []string
		total := 0
		for i := range c.Workloads {
			w := &c.Workloads[i]
			if w.Namespace != ns {
				continue
			}
			total++
			if !a.IngressIsolated(w) {
				open = append(open, w.Kind+"/"+w.Name)
			}
		}
		switch {
		case total == 0:
		case policiesIn[ns] == 0:
			add("NP001", "medium", "", "namespace "+ns,
				"has no NetworkPolicy: %s connections from every pod in the cluster and from outside it",
				map[bool]string{true: "its workload accepts", false: fmt.Sprintf("all %d of its workloads accept", total)}[total == 1])
		case len(open) > 0:
			add("NP001", "medium", "", "namespace "+ns,
				"has policies, but none selects %s: %s connections from everywhere. A default-deny policy (podSelector: {}) would close %s",
				strings.Join(open, ", "), plural(len(open), "this workload accepts", "these workloads accept"), plural(len(open), "it", "them"))
		}
	}

	for i := range c.Policies {
		p := &c.Policies[i]
		obj := "NetworkPolicy " + p.ID()
		out = append(out, a.policyShape(p, obj)...)

		// A policy that selects nothing is usually a label typo.
		selected := 0
		for j := range c.Workloads {
			w := &c.Workloads[j]
			if w.Namespace == p.Namespace && Matches(p.PodSelector, w.Labels) {
				selected++
			}
		}
		if selected == 0 && hasWorkloadsIn(c, p.Namespace) {
			add("NP002", "low", p.Source, obj, "selects no workload in namespace %s: check the podSelector labels", p.Namespace)
		}

		for _, side := range []struct {
			name  string
			rules []k8s.Rule
			on    bool
		}{{"ingress", p.Ingress, p.IngressType}, {"egress", p.Egress, p.EgressType}} {
			for _, r := range side.rules {
				peers := r.From
				if side.name == "egress" {
					peers = r.To
				}
				file := p.Source
				if i := strings.LastIndexByte(file, ':'); i > 0 {
					file = file[:i]
				}
				where := fmt.Sprintf("%s:%d", file, r.Line)
				out = append(out, a.peerFindings(p, peers, side.name, where, obj)...)
				if side.name == "ingress" && side.on {
					out = append(out, a.namedPorts(p, r, where, obj)...)
				}
			}
		}
	}

	// Egress isolation without DNS.
	for i := range c.Workloads {
		w := &c.Workloads[i]
		if !a.EgressIsolated(w) {
			continue
		}
		dns := Endpoint{External: true}
		if kd := kubeDNS(c); kd != nil {
			dns = Endpoint{Workload: kd}
		}
		udp := a.Allowed(Endpoint{Workload: w}, dns, 53, "UDP")
		tcp := a.Allowed(Endpoint{Workload: w}, dns, 53, "TCP")
		if !udp.EgressAllowed && !tcp.EgressAllowed && !anyEgressTo53(a, w) {
			add("NP005", "medium", w.Source, "workload "+w.ID(),
				"is egress-isolated and no egress rule allows port 53: its DNS lookups will fail, so it cannot reach services by name")
		}
	}

	sort.SliceStable(out, func(i, j int) bool {
		if Rank(out[i].Severity) != Rank(out[j].Severity) {
			return Rank(out[i].Severity) < Rank(out[j].Severity)
		}
		if out[i].Object != out[j].Object {
			return out[i].Object < out[j].Object
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func hasWorkloadsIn(c *k8s.Cluster, ns string) bool {
	for _, w := range c.Workloads {
		if w.Namespace == ns {
			return true
		}
	}
	return false
}

// kubeDNS finds the cluster DNS workload if the manifests include it.
func kubeDNS(c *k8s.Cluster) *k8s.Workload {
	for i := range c.Workloads {
		w := &c.Workloads[i]
		if w.Namespace == "kube-system" && (w.Labels["k8s-app"] == "kube-dns" || w.Name == "coredns") {
			return w
		}
	}
	return nil
}

// anyEgressTo53 reports an egress rule that allows port 53 to some destination, whether or not
// the DNS server is in the manifests.
func anyEgressTo53(a Analyzer, w *k8s.Workload) bool {
	for _, p := range a.Selecting(w) {
		if !p.EgressType {
			continue
		}
		for _, r := range p.Egress {
			if len(r.Ports) == 0 {
				return true
			}
			for _, port := range r.Ports {
				n := port.Number()
				if port.Port.Kind == 0 || n == 53 || port.EndPort != nil && n <= 53 && 53 <= *port.EndPort || port.Name() == "dns" {
					return true
				}
			}
		}
	}
	return false
}

func (a Analyzer) peerFindings(p *k8s.Policy, peers []k8s.Peer, side, where, obj string) []Finding {
	var out []Finding
	add := func(id, sev, format string, args ...any) {
		out = append(out, Finding{ID: id, Severity: sev, Where: where, Object: obj, Message: fmt.Sprintf(format, args...)})
	}
	nsOnly, podOnly := -1, -1
	for i, peer := range peers {
		switch {
		case peer.NamespaceSelector != nil && peer.PodSelector == nil && peer.IPBlock == nil:
			nsOnly = i
		case peer.PodSelector != nil && peer.NamespaceSelector == nil && peer.IPBlock == nil:
			podOnly = i
		}
		out = append(out, a.selectorMatchesNothing(p, peer, side, where, obj)...)
		if peer.IPBlock != nil {
			out = append(out, ipBlockFindings(peer.IPBlock, side, where, obj)...)
		}
		if peer.NamespaceSelector != nil && peer.PodSelector == nil && empty(*peer.NamespaceSelector) {
			dir := "from"
			if side == "egress" {
				dir = "to"
			}
			add("NP004", "low", "%s allows every pod in every namespace (namespaceSelector: {}), %s", side, dir+" anything in the cluster")
		}
	}
	if nsOnly >= 0 && podOnly >= 0 {
		add("NP003", "low",
			"%s lists a namespaceSelector and a podSelector as two separate peers, which means either one: every pod in the selected namespaces, or matching pods in this namespace. If the intent was matching pods in those namespaces, both selectors belong in one list item (one '-')", side)
	}
	return out
}

func empty(s k8s.Selector) bool { return len(s.MatchLabels) == 0 && len(s.MatchExpressions) == 0 }

func (a Analyzer) selectorMatchesNothing(p *k8s.Policy, peer k8s.Peer, side, where, obj string) []Finding {
	if peer.IPBlock != nil {
		return nil
	}
	var nsMatched []string
	if peer.NamespaceSelector != nil {
		for _, ns := range a.C.SortedNamespaces() {
			if Matches(*peer.NamespaceSelector, a.nsLabels(ns)) {
				nsMatched = append(nsMatched, ns)
			}
		}
		if len(nsMatched) == 0 {
			return []Finding{{ID: "NP002", Severity: "low", Where: where, Object: obj,
				Message: fmt.Sprintf("an %s namespaceSelector matches none of the namespaces in these manifests (%s); a namespace without a manifest has only its name label here", side, strings.Join(a.C.SortedNamespaces(), ", "))}}
		}
	} else {
		nsMatched = []string{p.Namespace}
	}
	if peer.PodSelector == nil {
		return nil
	}
	for _, w := range a.C.Workloads {
		if contains(nsMatched, w.Namespace) && Matches(*peer.PodSelector, w.Labels) {
			return nil
		}
	}
	return []Finding{{ID: "NP002", Severity: "low", Where: where, Object: obj,
		Message: fmt.Sprintf("an %s podSelector matches no workload in %s: check the labels", side, strings.Join(nsMatched, ", "))}}
}

func ipBlockFindings(b *k8s.IPBlock, side, where, obj string) []Finding {
	prefix, err := netip.ParsePrefix(b.CIDR)
	if err != nil {
		return []Finding{{ID: "NP010", Severity: "high", Where: where, Object: obj,
			Message: fmt.Sprintf("ipBlock cidr %q is not a CIDR; the API rejects the policy", b.CIDR)}}
	}
	var out []Finding
	for _, ex := range b.Except {
		e, err := netip.ParsePrefix(ex)
		if err != nil || !prefix.Contains(e.Addr()) || e.Bits() < prefix.Bits() {
			out = append(out, Finding{ID: "NP010", Severity: "high", Where: where, Object: obj,
				Message: fmt.Sprintf("ipBlock except %q is not a CIDR inside %s; the API rejects the policy", ex, b.CIDR)})
		}
	}
	if prefix.Bits() == 0 && side == "ingress" && len(b.Except) == 0 {
		out = append(out, Finding{ID: "NP004", Severity: "low", Where: where, Object: obj,
			Message: fmt.Sprintf("ingress allows %s: any address on the internet that can reach the pods", b.CIDR)})
	}
	return out
}

// namedPorts reports an ingress rule naming a port that none of the pods the policy selects declares.
func (a Analyzer) namedPorts(p *k8s.Policy, r k8s.Rule, where, obj string) []Finding {
	var out []Finding
	for _, port := range r.Ports {
		name := port.Name()
		if name == "" {
			continue
		}
		found := false
		for _, w := range a.C.Workloads {
			if w.Namespace != p.Namespace || !Matches(p.PodSelector, w.Labels) {
				continue
			}
			for _, cp := range w.Ports {
				if cp.Name == name && cp.Protocol == port.Proto() {
					found = true
				}
			}
		}
		if !found {
			out = append(out, Finding{ID: "NP006", Severity: "medium", Where: where, Object: obj,
				Message: fmt.Sprintf("ingress allows the named port %q (%s), but no pod this policy selects declares a port with that name: the rule lets nothing in", name, port.Proto())})
		}
	}
	return out
}

// policyShape reports specs the API rejects and sections it silently ignores.
func (a Analyzer) policyShape(p *k8s.Policy, obj string) []Finding {
	var out []Finding
	add := func(id, sev, format string, args ...any) {
		out = append(out, Finding{ID: id, Severity: sev, Where: p.Source, Object: obj, Message: fmt.Sprintf(format, args...)})
	}
	if len(p.Ingress) > 0 && !p.IngressType {
		add("NP007", "medium", "has ingress rules, but policyTypes does not list Ingress, so they are ignored")
	}
	if len(p.Egress) > 0 && !p.EgressType {
		add("NP007", "medium", "has egress rules, but policyTypes does not list Egress, so they are ignored")
	}
	if p.IngressType && len(p.Ingress) == 0 && p.EgressType && len(p.Egress) == 0 {
		add("NP008", "info", "denies all ingress and all egress for the pods it selects")
	}
	sels := []k8s.Selector{p.PodSelector}
	for _, rs := range [][]k8s.Rule{p.Ingress, p.Egress} {
		for _, r := range rs {
			for _, peer := range append(append([]k8s.Peer{}, r.From...), r.To...) {
				if peer.PodSelector != nil {
					sels = append(sels, *peer.PodSelector)
				}
				if peer.NamespaceSelector != nil {
					sels = append(sels, *peer.NamespaceSelector)
				}
				n := 0
				if peer.PodSelector != nil || peer.NamespaceSelector != nil {
					n++
				}
				if peer.IPBlock != nil {
					n++
				}
				if n != 1 {
					add("NP010", "high", "a peer must have an ipBlock or selectors, not both and not neither; the API rejects the policy")
				}
			}
			for _, port := range r.Ports {
				if port.EndPort != nil && (port.Number() == 0 || *port.EndPort < port.Number()) {
					add("NP010", "high", "endPort %d needs a numeric port no greater than it; the API rejects the policy", *port.EndPort)
				}
				switch port.Proto() {
				case "TCP", "UDP", "SCTP":
				default:
					add("NP010", "high", "protocol %q is not TCP, UDP or SCTP; the API rejects the policy", port.Protocol)
				}
			}
		}
	}
	for _, s := range sels {
		for _, r := range s.MatchExpressions {
			switch r.Operator {
			case "In", "NotIn":
				if len(r.Values) == 0 {
					add("NP010", "high", "matchExpressions %s %s needs values; the API rejects the policy", r.Key, r.Operator)
				}
			case "Exists", "DoesNotExist":
				if len(r.Values) > 0 {
					add("NP010", "high", "matchExpressions %s %s must not have values; the API rejects the policy", r.Key, r.Operator)
				}
			default:
				add("NP010", "high", "matchExpressions operator %q is not In, NotIn, Exists or DoesNotExist; the API rejects the policy", r.Operator)
			}
		}
	}
	return out
}
