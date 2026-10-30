package docker

import (
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/Ali7Zeynalli/depgate/internal/report"
)

// Stack lists what the project's Docker files run: every external image (Dockerfile
// FROM and compose services without build), the operating system it is built on
// and the system packages its Dockerfile stage installs. It is what DepGate's
// news are matched to. Only what the files say is known: an image pulled long
// ago may differ on the server.
func Stack(dir, repoRoot string) []report.ImageItem {
	var out []report.ImageItem
	for _, f := range discover(dir, repoRoot) {
		b, err := os.ReadFile(f.path)
		if err != nil || len(b) > maxFileSize {
			continue
		}
		if f.compose {
			root, err := parseYAML(string(b))
			if err != nil || root == nil {
				continue
			}
			svcs := root.get("services")
			if svcs == nil || svcs.Kind != yMap {
				continue
			}
			for _, e := range svcs.Keys {
				img := e.Val.get("image")
				if img == nil || img.Kind != yScalar || e.Val.get("build") != nil || strings.Contains(img.Value, "$") {
					continue
				}
				it := describe(img.Value)
				it.File, it.Line, it.Service = f.rel, img.Line, e.Name
				out = append(out, it)
			}
			continue
		}
		names := map[string]bool{}
		for _, st := range stages(parseDockerfile(string(b))) {
			low := strings.ToLower(st.Image)
			if st.Image == "" || low == "scratch" || strings.Contains(st.Image, "$") {
				continue
			}
			pkgs := installed(st)
			if names[low] { // FROM an earlier stage: its packages add to that stage's image
				if st.Name != "" {
					names[st.Name] = true
				}
				for i := len(out) - 1; i >= 0; i-- {
					if out[i].File == f.rel && strings.EqualFold(out[i].Image, st.rootImage()) {
						out[i].Packages = uniq(append(out[i].Packages, pkgs...))
						break
					}
				}
				continue
			}
			it := describe(st.Image)
			it.File, it.Line, it.Packages = f.rel, st.Line, pkgs
			out = append(out, it)
			if st.Name != "" {
				names[st.Name] = true
			}
		}
	}
	return out
}

// official images that are a product of their own (the name is the product)
var stackProducts = map[string]bool{
	"node": true, "python": true, "postgres": true, "redis": true, "nginx": true, "mysql": true, "mariadb": true,
	"mongo": true, "php": true, "golang": true, "ruby": true, "rabbitmq": true, "elasticsearch": true, "traefik": true,
	"memcached": true, "httpd": true, "haproxy": true, "valkey": true, "caddy": true, "keycloak": true, "grafana": true,
	"eclipse-temurin": true, "openjdk": true, "tomcat": true, "bun": true, "deno": true, "wordpress": true,
}

// images that ARE an operating system
var osImages = map[string]string{"debian": "debian", "ubuntu": "ubuntu", "alpine": "alpine"}

// images whose default (no OS in the tag) is Debian
var debianDefault = map[string]bool{
	"node": true, "python": true, "postgres": true, "redis": true, "nginx": true, "mysql": false, "mariadb": false,
	"php": true, "golang": true, "ruby": true, "httpd": true, "haproxy": true, "memcached": true, "rabbitmq": false,
}

var alpineTag = regexp.MustCompile(`^alpine(\d+\.\d+)?$`)

// describe reads an image reference: product, version, OS.
func describe(ref string) report.ImageItem {
	it := report.ImageItem{Image: ref}
	name, tag := ref, ""
	if i := strings.Index(name, "@"); i >= 0 {
		name = name[:i]
	}
	if i := strings.LastIndex(name, ":"); i > strings.LastIndex(name, "/") {
		name, tag = name[:i], name[i+1:]
	}
	short := strings.ToLower(name[strings.LastIndex(name, "/")+1:])
	official := !strings.Contains(name, "/") || strings.HasPrefix(name, "library/") || strings.HasPrefix(name, "docker.io/library/")
	it.Unpinned = tag == "" || tag == "latest"
	parts := strings.Split(tag, "-")
	if !it.Unpinned && len(parts) > 0 && (parts[0] != "" && (parts[0][0] >= '0' && parts[0][0] <= '9')) {
		it.Version = strings.TrimPrefix(parts[0], "v")
	}
	if official && stackProducts[short] {
		it.Product = short
	}
	if os, ok := osImages[short]; ok && official {
		it.OS = os
		switch {
		case it.Version != "":
			it.OSVersion = it.Version
			if os != "alpine" && strings.Count(it.OSVersion, ".") > 1 { // ubuntu 24.04.1 -> 24.04
				it.OSVersion = it.OSVersion[:strings.LastIndex(it.OSVersion, ".")]
			}
			if os == "alpine" && strings.Count(it.OSVersion, ".") > 1 {
				it.OSVersion = it.OSVersion[:strings.LastIndex(it.OSVersion, ".")]
			}
			if os == "debian" && strings.Contains(it.OSVersion, ".") {
				it.OSVersion = it.OSVersion[:strings.Index(it.OSVersion, ".")]
			}
		case tag != "" && tag != "latest":
			if c, ok := codenames[strings.ToLower(parts[0])]; ok {
				it.OSVersion = c[1]
			}
		}
		it.Version = ""
		return it
	}
	for _, v := range parts[1:] {
		lv := strings.ToLower(v)
		if c, ok := codenames[lv]; ok {
			it.OS, it.OSVersion = c[0], c[1]
		} else if m := alpineTag.FindStringSubmatch(lv); m != nil {
			it.OS, it.OSVersion = "alpine", m[1]
		}
	}
	if len(parts) > 0 && it.OS == "" { // node:alpine, node:bookworm
		lv := strings.ToLower(parts[0])
		if c, ok := codenames[lv]; ok {
			it.OS, it.OSVersion = c[0], c[1]
		} else if m := alpineTag.FindStringSubmatch(lv); m != nil {
			it.OS, it.OSVersion = "alpine", m[1]
		}
	}
	if it.OS == "" && official && debianDefault[short] {
		it.OS, it.OSGuess = "debian", true // the version follows the image's current default
	}
	return it
}

// codenames of Debian and Ubuntu releases in image tags
var codenames = map[string][2]string{
	"stretch": {"debian", "9"}, "buster": {"debian", "10"}, "bullseye": {"debian", "11"}, "bookworm": {"debian", "12"}, "trixie": {"debian", "13"},
	"bionic": {"ubuntu", "18.04"}, "focal": {"ubuntu", "20.04"}, "jammy": {"ubuntu", "22.04"}, "noble": {"ubuntu", "24.04"},
}

var pkgVersion = regexp.MustCompile(`[=<>].*$`)

// installed lists the packages `apt-get install`, `apt install` and `apk add` put in a stage.
func installed(st *stage) []string {
	var out []string
	for _, in := range st.Body {
		if in.Cmd != "RUN" {
			continue
		}
		for _, cmd := range splitShell(in.Args) {
			w := words(cmd)
			for len(w) > 0 && (w[0] == "sudo" || strings.Contains(w[0], "=")) { // sudo, DEBIAN_FRONTEND=…
				w = w[1:]
			}
			var args []string
			switch {
			case len(w) >= 2 && (w[0] == "apt-get" || w[0] == "apt") && contains(w[1:], "install"):
				args = w[indexOf(w, "install")+1:]
			case len(w) >= 2 && w[0] == "apk" && contains(w[1:], "add"):
				args = w[indexOf(w, "add")+1:]
			default:
				continue
			}
			for _, a := range args {
				a = pkgVersion.ReplaceAllString(a, "") // openssl=3.0.* → openssl
				if strings.HasPrefix(a, "-") || strings.ContainsAny(a, "$/*") || a == "" {
					continue
				}
				if a != "" {
					out = append(out, strings.ToLower(a))
				}
			}
		}
	}
	return uniq(out)
}

// splitShell cuts a RUN line at && ; || and |.
func splitShell(s string) []string {
	r := strings.NewReplacer("&&", "\n", "||", "\n", ";", "\n", "|", "\n")
	return strings.Split(r.Replace(s), "\n")
}

func contains(xs []string, x string) bool { return indexOf(xs, x) >= 0 }

func indexOf(xs []string, x string) int {
	for i, v := range xs {
		if v == x {
			return i
		}
	}
	return -1
}

func uniq(xs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}
