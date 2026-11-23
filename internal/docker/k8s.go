package docker

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Ali7Zeynalli/depgate/internal/i18n"
	"github.com/Ali7Zeynalli/depgate/internal/report"
)

// Kubernetes manifests and Helm values files: the images they run (so the end
// of life, patch release, nginx/Caddy and news checks cover them too) and a few
// pod security mistakes. Read line by line: no cluster is asked, nothing runs.

var (
	k8sKindRe    = regexp.MustCompile(`(?m)^kind:\s*["']?(Deployment|StatefulSet|DaemonSet|Job|CronJob|Pod|ReplicaSet|ReplicationController)\b`)
	k8sAPIRe     = regexp.MustCompile(`(?m)^apiVersion:`)
	helmValuesRe = regexp.MustCompile(`^values([.-][A-Za-z0-9_.-]+)?\.ya?ml$`)
	k8sImageRe   = regexp.MustCompile(`^(\s*)(?:-\s+)?image:\s*["']?([^\s"'#]+)["']?\s*(?:#.*)?$`)
	yamlKeyRe    = regexp.MustCompile(`^(\s*)(?:-\s+)?["']?([A-Za-z0-9_.-]+)["']?:\s*(.*?)\s*(?:#.*)?$`)
	docKindRe    = regexp.MustCompile(`^kind:\s*["']?([A-Za-z]+)`)
	metaNameRe   = regexp.MustCompile(`^  name:\s*["']?([^\s"'#]+)`)
)

// k8sKind tells whether a YAML file is a Kubernetes manifest with workloads
// ("manifest") or a Helm chart's values file ("helm"); "" otherwise.
func k8sKind(path, src string) string {
	name := filepath.Base(path)
	if helmValuesRe.MatchString(name) {
		if st, err := os.Stat(filepath.Join(filepath.Dir(path), "Chart.yaml")); err == nil && st.Mode().IsRegular() {
			return "helm"
		}
	}
	if k8sAPIRe.MatchString(src) && k8sKindRe.MatchString(src) {
		return "manifest"
	}
	return ""
}

// k8sImages returns the images of a manifest (Service = "Kind/name") or a Helm
// values file (Service = "Helm/<key>").
func k8sImages(rel, kind, src string) []ImageRef {
	if kind == "helm" {
		return helmImages(rel, src)
	}
	var out []ImageRef
	curKind, curName, inMeta := "", "", false
	for i, l := range strings.Split(src, "\n") {
		if strings.HasPrefix(l, "---") {
			curKind, curName, inMeta = "", "", false
			continue
		}
		if m := docKindRe.FindStringSubmatch(l); m != nil {
			curKind = m[1]
		}
		if strings.HasPrefix(l, "metadata:") {
			inMeta = true
			continue
		}
		if inMeta {
			if m := metaNameRe.FindStringSubmatch(l); m != nil && curName == "" {
				curName = m[1]
			}
			if l != "" && !strings.HasPrefix(l, " ") {
				inMeta = false
			}
		}
		m := k8sImageRe.FindStringSubmatch(l)
		if m == nil || strings.Contains(m[2], "{{") || strings.Contains(m[2], "$") {
			continue
		}
		svc := curKind
		if curName != "" {
			svc += "/" + curName
		}
		if svc == "" {
			svc = "Pod/?"
		}
		out = append(out, ImageRef{File: rel, Line: i + 1, Service: svc, Ref: m[2]})
	}
	return out
}

// helmImages reads `image:` blocks of a values file: repository + tag (+ registry).
func helmImages(rel, src string) []ImageRef {
	lines := strings.Split(src, "\n")
	type kv struct {
		indent    int
		key, val  string
		line      int
		parentKey string
	}
	var kvs []kv
	var stack []kv // open parents
	for i, l := range lines {
		if strings.TrimSpace(l) == "" || strings.HasPrefix(strings.TrimSpace(l), "#") {
			continue
		}
		m := yamlKeyRe.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		ind := len(m[1])
		for len(stack) > 0 && stack[len(stack)-1].indent >= ind {
			stack = stack[:len(stack)-1]
		}
		parent := ""
		if len(stack) > 0 {
			parent = stack[len(stack)-1].key
		}
		v := strings.Trim(m[3], `"'`)
		e := kv{ind, m[2], v, i + 1, parent}
		kvs = append(kvs, e)
		if m[3] == "" {
			stack = append(stack, e)
		}
	}
	var out []ImageRef
	for i, e := range kvs {
		if e.key != "repository" || e.val == "" || strings.Contains(e.val, "{{") {
			continue
		}
		tag, registry := "", ""
		for j := i - 3; j < len(kvs) && j <= i+6; j++ {
			if j < 0 || j == i || kvs[j].indent != e.indent || kvs[j].parentKey != e.parentKey {
				continue
			}
			switch kvs[j].key {
			case "tag":
				tag = kvs[j].val
			case "registry":
				registry = kvs[j].val
			}
		}
		ref := e.val
		if registry != "" && !strings.HasPrefix(ref, registry+"/") {
			ref = registry + "/" + ref
		}
		if tag != "" && !strings.Contains(tag, "{{") {
			ref += ":" + tag
		}
		key := e.parentKey
		if key == "" {
			key = "image"
		}
		out = append(out, ImageRef{File: rel, Line: e.line, Service: "Helm/" + key, Ref: ref})
	}
	// image: "nginx:1.27" as one string
	for _, e := range kvs {
		if e.key == "image" && e.val != "" && strings.Contains(e.val, ":") && !strings.Contains(e.val, "{{") && !strings.Contains(e.val, " ") {
			out = append(out, ImageRef{File: rel, Line: e.line, Service: "Helm/" + firstNonEmpty(e.parentKey, "image"), Ref: e.val})
		}
	}
	return out
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

var (
	k8sPrivRe    = regexp.MustCompile(`^\s*privileged:\s*true\b`)
	k8sHostRe    = regexp.MustCompile(`^\s*(hostNetwork|hostPID|hostIPC):\s*true\b`)
	k8sEscRe     = regexp.MustCompile(`^\s*allowPrivilegeEscalation:\s*true\b`)
	k8sRootRe    = regexp.MustCompile(`^\s*runAsUser:\s*0\s*(#.*)?$`)
	k8sHostPthRe = regexp.MustCompile(`^\s*path:\s*["']?(/|/etc|/root|/var/run/docker\.sock|/var/run|/proc|/sys)["']?\s*$`)
)

// checkK8s reviews a manifest for pod security mistakes.
func checkK8s(rel, src string) []report.DockerIssue {
	var out []report.DockerIssue
	add := func(line int, svc, rule, sev string, title, detail i18n.T, fix string) {
		out = append(out, report.DockerIssue{File: rel, Line: line, Service: svc, Rule: rule, Severity: sev, Title: title, Detail: detail, Fix: fix})
	}
	for _, r := range k8sImages(rel, "manifest", src) {
		if strings.Contains(r.Ref, "@sha256:") {
			continue
		}
		n, tag, _ := splitImage(r.Ref)
		if tag == "" || strings.EqualFold(tag, "latest") {
			add(r.Line, r.Service, "k8s-latest-tag", "medium",
				i18n.F("Image versiyası sabitlənməyib: %s", "Image version is not pinned: %s", r.Ref),
				i18n.F("`latest` və ya teqsiz image hər pod yenidən başlayanda fərqli versiya gətirə bilər.",
					"An untagged or `latest` image can bring a different version every time a pod restarts."), "image: "+n+":<version>")
		}
	}
	host := false
	for i, l := range strings.Split(src, "\n") {
		ln := i + 1
		switch {
		case k8sPrivRe.MatchString(l):
			add(ln, "", "k8s-privileged", "high",
				i18n.F("Konteyner privileged rejimdə işləyir", "Container runs in privileged mode"),
				i18n.F("privileged konteyner node-un bütün cihazlarına çıxış alır və izolyasiyanı faktiki olaraq ləğv edir.",
					"A privileged container gets every device of the node and effectively removes isolation."), "privileged: false")
		case k8sHostRe.MatchString(l):
			k := k8sHostRe.FindStringSubmatch(l)[1]
			add(ln, "", "k8s-host-namespace", "high",
				i18n.F("Pod node-un %s-ni paylaşır", "Pod shares the node's %s", k),
				i18n.F("Pod node-un şəbəkəsini və ya proseslərini görür; konteynerdəki bir zəiflik bütün node-a keçə bilər.",
					"The pod sees the node's network or processes; a hole in the container can reach the whole node."), k+": false")
		case k8sEscRe.MatchString(l):
			add(ln, "", "k8s-privilege-escalation", "medium",
				i18n.F("allowPrivilegeEscalation açıqdır", "allowPrivilegeEscalation is on"),
				i18n.F("Proses setuid ilə root ola bilər.", "A process can become root through setuid binaries."), "allowPrivilegeEscalation: false")
		case k8sRootRe.MatchString(l):
			add(ln, "", "k8s-run-as-root", "medium",
				i18n.F("Konteyner root (UID 0) kimi işləyir", "Container runs as root (UID 0)"),
				i18n.F("Root kimi işləmək tətbiqdəki hər səhvi böyüdür; imtiyazsız istifadəçi seç.",
					"Running as root magnifies any app bug; pick an unprivileged user."), "runAsUser: 10001\nrunAsNonRoot: true")
		case k8sHostPthRe.MatchString(l) && !host:
			host = true
			add(ln, "", "k8s-hostpath", "high",
				i18n.F("hostPath node-un həssas qovluğunu bağlayır", "hostPath mounts a sensitive folder of the node"),
				i18n.F("Docker socket-i, /etc və ya / pod-a verilərsə, pod node-u idarə edə bilər.",
					"With the Docker socket, /etc or / inside, the pod can take over the node."), "# use a PersistentVolumeClaim or a ConfigMap instead")
		}
	}
	return out
}
