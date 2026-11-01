// Package k8s reads the manifests a NetworkPolicy analysis needs: namespaces, the pods that
// workloads create, and the policies themselves.
package k8s

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// NameLabel is the label Kubernetes (1.21+) puts on every namespace, holding its name.
const NameLabel = "kubernetes.io/metadata.name"

// Namespace is a namespace and its labels.
type Namespace struct {
	Name   string
	Labels map[string]string
	// Declared is false for a namespace only referred to, whose labels other than its name are unknown.
	Declared bool
}

// ContainerPort is a port a pod's container declares.
type ContainerPort struct {
	Name     string
	Port     int
	Protocol string
}

// Workload is a group of identical pods: a Pod, or the template of a Deployment, StatefulSet,
// DaemonSet, ReplicaSet, Job or CronJob.
type Workload struct {
	Kind      string
	Name      string
	Namespace string
	Labels    map[string]string
	Ports     []ContainerPort
	Source    string
}

// ID is "namespace/Kind/name".
func (w Workload) ID() string { return w.Namespace + "/" + w.Kind + "/" + w.Name }

// Selector is a label selector.
type Selector struct {
	MatchLabels      map[string]string `yaml:"matchLabels"`
	MatchExpressions []Requirement     `yaml:"matchExpressions"`
}

// Requirement is one matchExpressions entry.
type Requirement struct {
	Key      string   `yaml:"key"`
	Operator string   `yaml:"operator"`
	Values   []string `yaml:"values"`
}

// IPBlock is a CIDR with exceptions.
type IPBlock struct {
	CIDR   string   `yaml:"cidr"`
	Except []string `yaml:"except"`
}

// Peer is one entry of a rule's from or to list.
type Peer struct {
	PodSelector       *Selector `yaml:"podSelector"`
	NamespaceSelector *Selector `yaml:"namespaceSelector"`
	IPBlock           *IPBlock  `yaml:"ipBlock"`
}

// Port is a rule's port: a number, a name or nothing (all ports), with an optional range end.
type Port struct {
	Protocol string    `yaml:"protocol"`
	Port     yaml.Node `yaml:"port"`
	EndPort  *int      `yaml:"endPort"`
}

// Number returns the port number, or 0 when the port is named or absent.
func (p Port) Number() int {
	if p.Port.Kind != yaml.ScalarNode {
		return 0
	}
	n, err := strconv.Atoi(p.Port.Value)
	if err != nil {
		return 0
	}
	return n
}

// Name returns the port's name when it is given as a string.
func (p Port) Name() string {
	if p.Port.Kind == yaml.ScalarNode && p.Number() == 0 {
		return p.Port.Value
	}
	return ""
}

// Proto is the protocol, TCP when unset.
func (p Port) Proto() string {
	if p.Protocol == "" {
		return "TCP"
	}
	return strings.ToUpper(p.Protocol)
}

// Rule is one ingress or egress rule. Peers is the from list (ingress) or the to list (egress);
// nil or empty means every peer.
type Rule struct {
	From  []Peer `yaml:"from"`
	To    []Peer `yaml:"to"`
	Ports []Port `yaml:"ports"`
	// Line is the rule's line in its file.
	Line int `yaml:"-"`
}

// Policy is a NetworkPolicy.
type Policy struct {
	Name        string
	Namespace   string
	PodSelector Selector
	Ingress     []Rule
	Egress      []Rule
	// Types is the effective policyTypes: Ingress always unless only Egress was listed, Egress
	// when listed or when an egress section exists.
	IngressType bool
	EgressType  bool
	Source      string
}

// ID is "namespace/name".
func (p Policy) ID() string { return p.Namespace + "/" + p.Name }

// Cluster is everything read.
type Cluster struct {
	Namespaces map[string]*Namespace
	Workloads  []Workload
	Policies   []Policy
	// Problems are documents that could not be used.
	Problems []string
}

type meta struct {
	Name      string            `yaml:"name"`
	Namespace string            `yaml:"namespace"`
	Labels    map[string]string `yaml:"labels"`
}

type podSpec struct {
	Containers []struct {
		Ports []struct {
			Name          string `yaml:"name"`
			ContainerPort int    `yaml:"containerPort"`
			Protocol      string `yaml:"protocol"`
		} `yaml:"ports"`
	} `yaml:"containers"`
	InitContainers []struct{} `yaml:"initContainers"`
}

type template struct {
	Metadata meta    `yaml:"metadata"`
	Spec     podSpec `yaml:"spec"`
}

type document struct {
	Kind     string      `yaml:"kind"`
	Metadata meta        `yaml:"metadata"`
	Items    []yaml.Node `yaml:"items"`
	Spec     yaml.Node   `yaml:"spec"`
}

// New returns an empty cluster.
func New() *Cluster { return &Cluster{Namespaces: map[string]*Namespace{}} }

// Read adds every document in a YAML stream. defaultNS is the namespace for objects that do not
// name one, as kubectl apply would use.
func (c *Cluster) Read(name string, data []byte, defaultNS string) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	for i := 0; ; i++ {
		var node yaml.Node
		err := dec.Decode(&node)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%s: document %d: %v", name, i+1, err)
		}
		c.node(name, &node, defaultNS)
	}
}

func (c *Cluster) node(name string, node *yaml.Node, defaultNS string) {
	var doc document
	if err := node.Decode(&doc); err != nil {
		c.Problems = append(c.Problems, fmt.Sprintf("%s:%d: %v", name, node.Line, err))
		return
	}
	where := fmt.Sprintf("%s:%d", name, node.Line)
	ns := doc.Metadata.Namespace
	if ns == "" {
		ns = defaultNS
	}
	switch doc.Kind {
	case "":
		return
	case "List":
		for i := range doc.Items {
			c.node(name, &doc.Items[i], defaultNS)
		}
	case "Namespace":
		n := c.namespace(doc.Metadata.Name)
		n.Declared = true
		for k, v := range doc.Metadata.Labels {
			n.Labels[k] = v
		}
		// The API server always sets this label to the namespace's own name, whatever a
		// manifest says, so a manifest cannot make one namespace look like another to a
		// namespaceSelector.
		if v, ok := doc.Metadata.Labels[NameLabel]; ok && v != doc.Metadata.Name {
			c.Problems = append(c.Problems, fmt.Sprintf("%s: Namespace %s sets %s=%s; the API server replaces it with the namespace's name",
				where, doc.Metadata.Name, NameLabel, v))
		}
		n.Labels[NameLabel] = doc.Metadata.Name
	case "Pod":
		var spec podSpec
		_ = doc.Spec.Decode(&spec)
		c.workload(doc.Kind, doc.Metadata.Name, ns, doc.Metadata.Labels, spec, where)
	case "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "ReplicationController", "Job":
		var spec struct {
			Template template `yaml:"template"`
		}
		_ = doc.Spec.Decode(&spec)
		c.workload(doc.Kind, doc.Metadata.Name, ns, spec.Template.Metadata.Labels, spec.Template.Spec, where)
	case "CronJob":
		var spec struct {
			JobTemplate struct {
				Spec struct {
					Template template `yaml:"template"`
				} `yaml:"spec"`
			} `yaml:"jobTemplate"`
		}
		_ = doc.Spec.Decode(&spec)
		t := spec.JobTemplate.Spec.Template
		c.workload(doc.Kind, doc.Metadata.Name, ns, t.Metadata.Labels, t.Spec, where)
	case "NetworkPolicy":
		c.policy(doc, ns, where)
	}
}

func (c *Cluster) namespace(name string) *Namespace {
	n, ok := c.Namespaces[name]
	if !ok {
		n = &Namespace{Name: name, Labels: map[string]string{NameLabel: name}}
		c.Namespaces[name] = n
	}
	return n
}

func (c *Cluster) workload(kind, name, ns string, labels map[string]string, spec podSpec, where string) {
	c.namespace(ns)
	w := Workload{Kind: kind, Name: name, Namespace: ns, Labels: labels, Source: where}
	if w.Labels == nil {
		w.Labels = map[string]string{}
	}
	for _, ct := range spec.Containers {
		for _, p := range ct.Ports {
			proto := strings.ToUpper(p.Protocol)
			if proto == "" {
				proto = "TCP"
			}
			w.Ports = append(w.Ports, ContainerPort{Name: p.Name, Port: p.ContainerPort, Protocol: proto})
		}
	}
	c.Workloads = append(c.Workloads, w)
}

func (c *Cluster) policy(doc document, ns, where string) {
	var spec struct {
		PodSelector Selector  `yaml:"podSelector"`
		PolicyTypes []string  `yaml:"policyTypes"`
		Ingress     yaml.Node `yaml:"ingress"`
		Egress      yaml.Node `yaml:"egress"`
	}
	if err := doc.Spec.Decode(&spec); err != nil {
		c.Problems = append(c.Problems, fmt.Sprintf("%s: NetworkPolicy %s: %v", where, doc.Metadata.Name, err))
		return
	}
	p := Policy{Name: doc.Metadata.Name, Namespace: ns, PodSelector: spec.PodSelector, Source: where}
	var err error
	if p.Ingress, err = rules(&spec.Ingress); err != nil {
		c.Problems = append(c.Problems, fmt.Sprintf("%s: NetworkPolicy %s ingress: %v", where, p.Name, err))
		return
	}
	if p.Egress, err = rules(&spec.Egress); err != nil {
		c.Problems = append(c.Problems, fmt.Sprintf("%s: NetworkPolicy %s egress: %v", where, p.Name, err))
		return
	}
	if len(spec.PolicyTypes) == 0 {
		// The API's default: Ingress, plus Egress if the policy has an egress section.
		p.IngressType = true
		p.EgressType = present(&spec.Egress)
	}
	for _, t := range spec.PolicyTypes {
		switch t {
		case "Ingress":
			p.IngressType = true
		case "Egress":
			p.EgressType = true
		default:
			c.Problems = append(c.Problems, fmt.Sprintf("%s: NetworkPolicy %s: policyTypes %q is neither Ingress nor Egress", where, p.Name, t))
		}
	}
	c.namespace(ns)
	c.Policies = append(c.Policies, p)
}

// present reports a YAML field that is set to something other than null. The API treats
// "egress: null" (or "~", or an alias of a null) as no egress section at all.
func present(n *yaml.Node) bool {
	for i := 0; n != nil && n.Kind == yaml.AliasNode && i < 16; i++ {
		n = n.Alias
	}
	return n != nil && n.Kind != 0 && n.Kind != yaml.AliasNode && !(n.Kind == yaml.ScalarNode && n.ShortTag() == "!!null")
}

func rules(n *yaml.Node) ([]Rule, error) {
	if !present(n) {
		return nil, nil
	}
	var out []Rule
	if err := n.Decode(&out); err != nil {
		return nil, err
	}
	for i := range out {
		if i < len(n.Content) {
			out[i].Line = n.Content[i].Line
		}
	}
	if out == nil {
		out = []Rule{}
	}
	return out, nil
}

// SortedNamespaces lists namespace names in order.
func (c *Cluster) SortedNamespaces() []string {
	var out []string
	for n := range c.Namespaces {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
