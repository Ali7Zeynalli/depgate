package docker

import (
	"os"
	"path/filepath"
	"testing"
)

func TestKubernetes(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, s string) {
		p := filepath.Join(dir, rel)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("package.json", `{"name":"x"}`)
	write("k8s/api.yaml", `apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  template:
    spec:
      hostNetwork: true
      containers:
        - name: api
          image: "node:22.20.0-bookworm-slim"
          securityContext:
            privileged: true
            runAsUser: 0
        - name: side
          image: redis
---
apiVersion: batch/v1
kind: CronJob
metadata:
  name: backup
spec:
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - image: postgres:16.4 # nightly dump
`)
	write("k8s/config.yaml", "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: c\n")
	write("charts/web/Chart.yaml", "name: web\n")
	write("charts/web/values.yaml", `replicaCount: 2
image:
  registry: docker.io
  repository: library/nginx
  tag: "1.27.1"
redis:
  image:
    repository: bitnami/redis
    tag: 7.4.1
`)
	write("charts/web/templates/deploy.yaml", "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: {{ .Release.Name }}\nspec:\n  template:\n    spec:\n      containers:\n        - image: \"{{ .Values.image.repository }}:{{ .Values.image.tag }}\"\n")

	refs := ImageRefs(dir, "")
	got := map[string]string{}
	for _, r := range refs {
		got[r.Ref] = r.Service + "@" + r.File
	}
	want := map[string]string{
		"node:22.20.0-bookworm-slim":     "Deployment/api@k8s/api.yaml",
		"redis":                          "Deployment/api@k8s/api.yaml",
		"postgres:16.4":                  "CronJob/backup@k8s/api.yaml",
		"docker.io/library/nginx:1.27.1": "Helm/image@charts/web/values.yaml",
		"bitnami/redis:7.4.1":            "Helm/image@charts/web/values.yaml",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got %q want %q (all %v)", k, got[k], v, got)
		}
	}
	if len(refs) != len(want) {
		t.Errorf("refs %v", got)
	}
	issues, files := Scan(dir, "")
	rules := map[string]int{}
	for _, is := range issues {
		rules[is.Rule]++
	}
	for _, r := range []string{"k8s-privileged", "k8s-host-namespace", "k8s-run-as-root", "k8s-latest-tag"} {
		if rules[r] != 1 {
			t.Errorf("rule %s: %d (%v)", r, rules[r], rules)
		}
	}
	if len(files) != 3 { // api.yaml, values.yaml, the template (a workload too); not the ConfigMap
		t.Errorf("files %v", files)
	}
	if st := Stack(dir, ""); len(st) != len(want) {
		t.Errorf("stack %d", len(st))
	}
}
