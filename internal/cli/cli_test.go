package cli

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func run(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := Run(args, strings.NewReader(stdin), &out, &errb)
	return code, out.String(), errb.String()
}

const shop = "../../testdata/shop.yaml"

func TestFindings(t *testing.T) {
	code, out, _ := run(t, "", shop)
	if code != 1 || !strings.Contains(out, "NP003") || !strings.Contains(out, "7 workload(s), 6 NetworkPolicy(ies)") {
		t.Fatalf("%d\n%s", code, out)
	}
	if code, _, _ := run(t, "", shop, "--fail-on", "high"); code != 0 {
		t.Fatalf("no high findings: %d", code)
	}
}

func TestCan(t *testing.T) {
	for q, want := range map[string]int{
		"shop/frontend shop/api 9000":           0,
		"shop/frontend shop/db 5432":            1,
		"shop/api shop/StatefulSet/db 5432/tcp": 0,
		"outside shop/frontend 8080":            1,
		"outside legacy/reports 8080":           0,
		"shop/db outside 443":                   1,
	} {
		code, out, errOut := run(t, "", shop, "--can", q)
		if code != want {
			t.Errorf("%s: exit %d\n%s%s", q, code, out, errOut)
		}
	}
}

func TestCanErrors(t *testing.T) {
	for _, q := range []string{"shop/frontend shop/api", "nope/x shop/api 80", "shop/frontend shop/api http", "outside outside 80", "shop/frontend shop/api 70000"} {
		if code, _, errOut := run(t, "", shop, "--can", q); code != 2 || errOut == "" {
			t.Errorf("%q: %d %q", q, code, errOut)
		}
	}
}

func TestAmbiguousName(t *testing.T) {
	yaml := "kind: Pod\nmetadata: {name: x}\nspec: {containers: [{name: c}]}\n---\nkind: Deployment\nmetadata: {name: x}\nspec: {template: {metadata: {labels: {a: b}}, spec: {containers: [{name: c}]}}}\n"
	if code, _, errOut := run(t, yaml, "-", "--can", "default/x default/Pod/x 80"); code != 2 || !strings.Contains(errOut, "more than one") {
		t.Fatalf("%d %s", code, errOut)
	}
	if code, _, _ := run(t, yaml, "-", "--can", "default/Deployment/x default/Pod/x 80"); code != 0 {
		t.Fatal("Kind disambiguates")
	}
}

func TestMatrix(t *testing.T) {
	_, out, _ := run(t, "", shop, "--matrix")
	for _, want := range []string{
		"shop/StatefulSet/db 5432/TCP (postgres) <- shop/Deployment/api\n",
		"shop/Deployment/api 9100/TCP (prom) <- nothing\n",
		"shop/CronJob/payments-sync 80/TCP (declares no ports; 80 tested) <- nothing\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
}

func TestMatrixSummarisesEveryone(t *testing.T) {
	yaml := "kind: Pod\nmetadata: {name: a}\nspec: {containers: [{name: c, ports: [{containerPort: 80}]}]}\n---\n" +
		"kind: Pod\nmetadata: {name: b}\nspec: {containers: [{name: c}]}\n"
	_, out, _ := run(t, yaml, "-", "--matrix")
	if !strings.Contains(out, "default/Pod/a 80/TCP <- every workload, and outside the cluster\n") {
		t.Fatal(out)
	}
}

func TestJSONAndErrors(t *testing.T) {
	_, out, _ := run(t, "", shop, "--json")
	var res struct {
		Workloads int `json:"workloads"`
		Findings  []struct{ ID, Severity, Object, Message, Where string }
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil || res.Workloads != 7 || len(res.Findings) == 0 {
		t.Fatalf("%v %+v", err, res)
	}
	for name, args := range map[string][]string{
		"no path": {}, "missing": {filepath.Join(t.TempDir(), "x.yaml")}, "bad fail-on": {"--fail-on", "x", shop}, "unknown": {"--nope", shop},
	} {
		if code, _, errOut := run(t, "", args...); code != 2 || errOut == "" {
			t.Errorf("%s: %d", name, code)
		}
	}
	if code, _, _ := run(t, "kind: Pod\n  bad: [\n", "-"); code != 2 {
		t.Error("broken YAML")
	}
}

func TestVersionAndHelp(t *testing.T) {
	if code, out, _ := run(t, "", "--version"); code != 0 || !strings.HasPrefix(out, "netpolwarden ") {
		t.Fatal(out)
	}
	if code, out, _ := run(t, "", "--help"); code != 0 || !strings.Contains(out, "usage:") {
		t.Fatal(out)
	}
}
