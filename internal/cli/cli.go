// Package cli is netpolwarden's command line.
package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/sriharifortitude/netpolwarden/internal/k8s"
	"github.com/sriharifortitude/netpolwarden/internal/netpol"
)

// Version is the release.
var Version = "0.1.0"

const maxFileBytes = 16 << 20

const usage = `netpolwarden: work out who can reach whom under Kubernetes NetworkPolicies.

usage: netpolwarden [flags] PATH...

PATH is a YAML file or a directory of them (*.yaml, *.yml): Namespaces, workloads (Pod,
Deployment, StatefulSet, DaemonSet, ReplicaSet, Job, CronJob) and NetworkPolicies, as
written or as "kubectl get -o yaml" prints them. - reads standard input. The manifests
must be the whole picture: a policy left out is a policy not counted.

flags:
  --can "SRC DST PORT[/PROTO]"   answer one question: SRC and DST are namespace/name or
                                 namespace/Kind/name, or "outside"
  --matrix                       print which workloads can reach which, per port
  --namespace NS                 namespace for objects that name none (default "default")
  --fail-on LEVEL                exit 1 at or above: critical, high, medium (default), low, info, none
  --json                         machine-readable findings
  --version

exit status: 0 nothing at or above --fail-on (or, with --can, the connection is allowed),
1 a finding is (or the connection is denied), 2 usage error or unreadable input
`

// Run executes the command and returns the exit status.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("netpolwarden", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	can := fs.String("can", "", "")
	matrix := fs.Bool("matrix", false, "")
	defaultNS := fs.String("namespace", "default", "")
	failOn := fs.String("fail-on", "medium", "")
	asJSON := fs.Bool("json", false, "")
	showVersion := fs.Bool("version", false, "")
	help := fs.Bool("help", false, "")

	var paths []string
	rest := args
	for len(rest) > 0 {
		if err := fs.Parse(rest); err != nil {
			fmt.Fprintf(stderr, "netpolwarden: %v\n\n%s", err, usage)
			return 2
		}
		rest = fs.Args()
		if len(rest) > 0 {
			paths = append(paths, rest[0])
			rest = rest[1:]
		}
	}
	switch {
	case *help:
		fmt.Fprint(stdout, usage)
		return 0
	case *showVersion:
		fmt.Fprintf(stdout, "netpolwarden %s\n", Version)
		return 0
	case len(paths) == 0:
		fmt.Fprint(stderr, usage)
		return 2
	case *failOn != "none" && netpol.Rank(*failOn) == len(netpol.Severities):
		fmt.Fprintf(stderr, "netpolwarden: --fail-on must be critical, high, medium, low, info or none, not %q\n", *failOn)
		return 2
	}

	c := k8s.New()
	for _, p := range paths {
		files, err := expand(p)
		if err != nil {
			fmt.Fprintf(stderr, "netpolwarden: %v\n", err)
			return 2
		}
		for _, f := range files {
			data, err := readCapped(f, stdin)
			if err != nil {
				fmt.Fprintf(stderr, "netpolwarden: %v\n", err)
				return 2
			}
			if err := c.Read(filepath.ToSlash(f), data, *defaultNS); err != nil {
				fmt.Fprintf(stderr, "netpolwarden: %v\n", err)
				return 2
			}
		}
	}
	a := netpol.Analyzer{C: c}

	if *can != "" {
		return query(a, *can, stdout, stderr)
	}
	if *matrix {
		fmt.Fprint(stdout, Matrix(a))
		return 0
	}

	findings := netpol.Check(c)
	if *asJSON {
		if findings == nil {
			findings = []netpol.Finding{}
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		if err := enc.Encode(map[string]any{"workloads": len(c.Workloads), "policies": len(c.Policies), "findings": findings}); err != nil {
			return 2
		}
	} else {
		fmt.Fprint(stdout, Render(c, findings))
	}
	for _, f := range findings {
		if *failOn != "none" && netpol.Rank(f.Severity) <= netpol.Rank(*failOn) {
			return 1
		}
	}
	return 0
}

func expand(p string) ([]string, error) {
	if p == "-" {
		return []string{"-"}, nil
	}
	info, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return []string{p}, nil
	}
	var out []string
	err = filepath.WalkDir(p, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if d.Type().IsRegular() && (ext == ".yaml" || ext == ".yml") {
			out = append(out, path)
		}
		return nil
	})
	sort.Strings(out)
	return out, err
}

func readCapped(path string, stdin io.Reader) ([]byte, error) {
	var r io.Reader = stdin
	if path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}
	data, err := io.ReadAll(io.LimitReader(r, maxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxFileBytes {
		return nil, fmt.Errorf("%s is over %d MiB", path, maxFileBytes>>20)
	}
	return data, nil
}

// find resolves "outside", "namespace/name" or "namespace/Kind/name".
func find(c *k8s.Cluster, ref string) (netpol.Endpoint, error) {
	if ref == "outside" {
		return netpol.Endpoint{External: true}, nil
	}
	parts := strings.Split(ref, "/")
	var hits []*k8s.Workload
	for i := range c.Workloads {
		w := &c.Workloads[i]
		switch len(parts) {
		case 2:
			if w.Namespace == parts[0] && w.Name == parts[1] {
				hits = append(hits, w)
			}
		case 3:
			if w.Namespace == parts[0] && strings.EqualFold(w.Kind, parts[1]) && w.Name == parts[2] {
				hits = append(hits, w)
			}
		}
	}
	switch len(hits) {
	case 0:
		return netpol.Endpoint{}, fmt.Errorf("no workload %q in the manifests", ref)
	case 1:
		return netpol.Endpoint{Workload: hits[0]}, nil
	}
	return netpol.Endpoint{}, fmt.Errorf("%q names more than one workload; use namespace/Kind/name", ref)
}

func query(a netpol.Analyzer, q string, stdout, stderr io.Writer) int {
	f := strings.Fields(q)
	if len(f) != 3 {
		fmt.Fprintln(stderr, `netpolwarden: --can takes "SRC DST PORT[/PROTO]"`)
		return 2
	}
	src, err := find(a.C, f[0])
	if err == nil && src.External && f[1] == "outside" {
		err = fmt.Errorf("both ends are outside the cluster")
	}
	if err != nil {
		fmt.Fprintf(stderr, "netpolwarden: %v\n", err)
		return 2
	}
	dst, err := find(a.C, f[1])
	if err != nil {
		fmt.Fprintf(stderr, "netpolwarden: %v\n", err)
		return 2
	}
	portStr, proto, _ := strings.Cut(f[2], "/")
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		fmt.Fprintf(stderr, "netpolwarden: %q is not a port number\n", portStr)
		return 2
	}
	if proto == "" {
		proto = "TCP"
	}
	proto = strings.ToUpper(proto)
	v := a.Allowed(src, dst, port, proto)
	fmt.Fprint(stdout, netpol.Explain(src, dst, port, proto, v))
	if v.Allowed {
		return 0
	}
	return 1
}

// Matrix lists, for each workload and each port it declares, which workloads can connect.
func Matrix(a netpol.Analyzer) string {
	var b strings.Builder
	ws := a.C.Workloads
	sort.SliceStable(ws, func(i, j int) bool { return ws[i].ID() < ws[j].ID() })
	for i := range ws {
		dst := netpol.Endpoint{Workload: &ws[i]}
		for _, probe := range netpol.ProbesFor(&ws[i]) {
			var from []string
			everyone := true
			for j := range ws {
				if i == j {
					continue
				}
				if a.Allowed(netpol.Endpoint{Workload: &ws[j]}, dst, probe.Port, probe.Proto).Allowed {
					from = append(from, ws[j].ID())
				} else {
					everyone = false
				}
			}
			outside := a.Allowed(netpol.Endpoint{External: true}, dst, probe.Port, probe.Proto).Allowed
			label := fmt.Sprintf("%d/%s", probe.Port, probe.Proto)
			switch {
			case probe.Name != "":
				label += " (" + probe.Name + ")"
			case len(ws[i].Ports) == 0:
				label += " (declares no ports; 80 tested)"
			}
			who := strings.Join(from, ", ")
			switch {
			case everyone && outside:
				who = "every workload, and outside the cluster"
			case everyone:
				who = "every workload"
			case len(from) == 0 && !outside:
				who = "nothing"
			case outside && len(from) == 0:
				who = "outside the cluster only"
			case outside:
				who += ", and outside the cluster"
			}
			fmt.Fprintf(&b, "%s %s <- %s\n", ws[i].ID(), label, who)
		}
	}
	return b.String()
}

// Render formats findings as text.
func Render(c *k8s.Cluster, findings []netpol.Finding) string {
	var b strings.Builder
	for _, f := range findings {
		where := ""
		if f.Where != "" {
			where = "  (" + f.Where + ")"
		}
		fmt.Fprintf(&b, "%s %-8s %s %s%s\n", f.ID, f.Severity, f.Object, f.Message, where)
	}
	counts := map[string]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	var parts []string
	for _, s := range netpol.Severities {
		if counts[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[s], s))
		}
	}
	summary := "no findings"
	if len(parts) > 0 {
		summary = strings.Join(parts, ", ")
	}
	fmt.Fprintf(&b, "%d workload(s), %d NetworkPolicy(ies) in %d namespace(s); %s\n", len(c.Workloads), len(c.Policies), len(c.Namespaces), summary)
	return b.String()
}
