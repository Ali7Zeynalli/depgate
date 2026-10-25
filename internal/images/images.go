// Package images checks the container images a project uses against
// endoflife.date: end-of-life release lines, lines that end soon, pinned
// versions that miss newer patch releases, and end-of-life OS variants
// (node:18-buster, python:3.12-alpine3.16, ...).
//
// It does not pull images or list the packages inside them; for that a
// scanner such as Trivy is needed.
package images

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Ali7Zeynalli/depgate/internal/docker"
	"github.com/Ali7Zeynalli/depgate/internal/i18n"
	"github.com/Ali7Zeynalli/depgate/internal/report"
	"github.com/Ali7Zeynalli/depgate/internal/sources"
)

// products maps Docker Hub image names to endoflife.date products (first match wins).
var products = map[string][]string{
	"python": {"python"}, "postgres": {"postgresql"}, "redis": {"redis"}, "nginx": {"nginx"},
	"alpine": {"alpine-linux", "alpine"}, "debian": {"debian"}, "ubuntu": {"ubuntu"},
	"mysql": {"mysql"}, "mariadb": {"mariadb"}, "mongo": {"mongodb"}, "php": {"php"}, "golang": {"go"},
	"ruby": {"ruby"}, "rabbitmq": {"rabbitmq"}, "elasticsearch": {"elasticsearch"}, "eclipse-temurin": {"eclipse-temurin"},
	"traefik": {"traefik"}, "memcached": {"memcached"}, "httpd": {"apache-http-server"}, "haproxy": {"haproxy"},
	"valkey": {"valkey"}, "keycloak": {"keycloak"}, "grafana": {"grafana"}, "nextcloud": {"nextcloud"},
	"wordpress": {"wordpress"}, "tomcat": {"tomcat"}, "kibana": {"kibana"}, "consul": {"consul"}, "vault": {"hashicorp-vault"},
	// node images: the Node line itself is checked by the Node.js card; only the OS variant is checked here
}

// os variants carried in tags
var codenames = map[string][2]string{
	"stretch": {"debian", "9"}, "buster": {"debian", "10"}, "bullseye": {"debian", "11"}, "bookworm": {"debian", "12"}, "trixie": {"debian", "13"},
	"bionic": {"ubuntu", "18.04"}, "focal": {"ubuntu", "20.04"}, "jammy": {"ubuntu", "22.04"}, "noble": {"ubuntu", "24.04"},
}

// Check returns issues for the image references. Lookups that fail are skipped.
func Check(ctx context.Context, f sources.Fetcher, refs []docker.ImageRef, now time.Time) []report.DockerIssue {
	cache := map[string][]sources.Cycle{}
	cycles := func(product string) []sources.Cycle {
		if cs, ok := cache[product]; ok {
			return cs
		}
		cs, err := sources.Cycles(ctx, f, product)
		if err != nil {
			cs = nil
		}
		cache[product] = cs
		return cs
	}
	var out []report.DockerIssue
	seen := map[string]bool{}
	for _, r := range refs {
		name, tag := split(r.Ref)
		if tag == "" || tag == "latest" {
			continue // unpinned images are reported by the Docker rules
		}
		short := name[strings.LastIndex(name, "/")+1:]
		if strings.Contains(name, "/") && !strings.HasPrefix(name, "library/") && !strings.HasPrefix(name, "docker.io/library/") {
			continue // only official images map cleanly to a product
		}
		ver, variant := versionOf(tag)
		add := func(rule, sev string, title, detail i18n.T, fix string) {
			k := r.File + ":" + strconv.Itoa(r.Line) + ":" + rule
			if seen[k] {
				return
			}
			seen[k] = true
			out = append(out, report.DockerIssue{File: r.File, Line: r.Line, Service: r.Service, Rule: rule, Severity: sev, Title: title, Detail: detail, Fix: fix})
		}

		// the image's own release line
		if cands, ok := products[short]; ok && ver != "" {
			for _, p := range cands {
				cs := cycles(p)
				if len(cs) == 0 {
					continue
				}
				c, ok := match(cs, ver, short)
				if !ok {
					break
				}
				next := newest(cs, now, short == "debian" || short == "ubuntu")
				switch {
				case c.Ended(now):
					add("image-eol", "high",
						i18n.F("%s %s dəstəyi bitib", "%s %s has reached end of life", short, c.Name),
						i18n.F("%s tarixindən təhlükəsizlik düzəlişləri çıxmır; image-dəki boşluqlar düzəlməyəcək.", "No security fixes since %s; vulnerabilities in this image will not be fixed.", date(c)),
						fixTag(name, next, variant))
				case !c.EOL.IsZero() && c.EOL.Sub(now) < 120*24*time.Hour:
					add("image-eol-soon", "medium",
						i18n.F("%s %s dəstəyi tezliklə bitir (%s)", "%s %s reaches end of life soon (%s)", short, c.Name, c.EOL.Format("2006-01-02")),
						i18n.F("Bitməzdən əvvəl daha yeni xəttə keçməyi planla.", "Plan the move to a newer line before it ends."),
						fixTag(name, next, variant))
				}
				// pinned to a patch that is behind the newest of its line
				if c.Latest != "" && precise(ver, c.Name) && less(ver, c.Latest) && !c.Ended(now) {
					add("image-outdated-patch", "medium",
						i18n.F("%s:%s köhnə patch versiyasıdır (son: %s)", "%s:%s is an old patch release (latest: %s)", short, ver, c.Latest),
						i18n.F("Eyni xəttin yeni patch relizləri adətən təhlükəsizlik düzəlişləri gətirir; kod dəyişikliyi lazım deyil.", "Newer patch releases of the same line usually carry security fixes and need no code change."),
						name+":"+c.Latest+suffix(variant))
				}
				break
			}
		}

		// the OS the image is built on
		for _, v := range variant {
			product, cycle := "", ""
			if c, ok := codenames[v]; ok {
				product, cycle = c[0], c[1]
			} else if strings.HasPrefix(v, "alpine") && len(v) > 6 {
				product, cycle = "alpine-linux", strings.TrimPrefix(v, "alpine")
			}
			if product == "" {
				continue
			}
			cs := cycles(product)
			if len(cs) == 0 && product == "alpine-linux" {
				cs = cycles("alpine")
			}
			c, ok := match(cs, cycle, product)
			if !ok || !c.Ended(now) {
				continue
			}
			add("image-os-eol", "high",
				i18n.F("Image-in əməliyyat sistemi köhnəlib: %s", "The image's operating system is end of life: %s", v),
				i18n.F("%s %s %s tarixindən yamaq almır; image-in içindəki sistem paketlərinin boşluqları düzəlməyəcək.", "%s %s gets no patches since %s; vulnerabilities in the image's system packages will not be fixed.", product, cycle, date(c)),
				r.Ref[:strings.LastIndex(r.Ref, ":")+1]+replaceVariant(tag, v, product))
		}
	}
	return out
}

func split(ref string) (name, tag string) {
	if i := strings.Index(ref, "@"); i >= 0 {
		return strings.ToLower(ref[:i]), "" // pinned by digest: nothing to read from the tag
	}
	slash := strings.LastIndex(ref, "/")
	if c := strings.LastIndex(ref, ":"); c > slash {
		return strings.ToLower(ref[:c]), strings.ToLower(ref[c+1:])
	}
	return strings.ToLower(ref), ""
}

// versionOf splits "3.12.1-slim-bookworm" into "3.12.1" and [slim bookworm];
// a tag without a version ("bookworm", "jammy") becomes a codename version.
func versionOf(tag string) (string, []string) {
	parts := strings.Split(strings.TrimPrefix(tag, "v"), "-")
	if len(parts[0]) > 0 && parts[0][0] >= '0' && parts[0][0] <= '9' {
		return parts[0], parts[1:]
	}
	if _, ok := codenames[parts[0]]; ok {
		return parts[0], parts[1:]
	}
	return "", parts
}

// match finds the cycle a version belongs to: "15.4" → "15", "3.12.1" → "3.12", codenames too.
func match(cs []sources.Cycle, ver, product string) (sources.Cycle, bool) {
	if c, ok := codenames[ver]; ok {
		ver = c[1]
	}
	segs := strings.Split(ver, ".")
	for n := len(segs); n >= 1; n-- {
		want := strings.Join(segs[:n], ".")
		for _, c := range cs {
			if c.Name == want || c.Code == ver {
				return c, true
			}
		}
	}
	return sources.Cycle{}, false
}

// newest returns the newest supported line (LTS first when the product has LTS lines).
func newest(cs []sources.Cycle, now time.Time, ltsOnly bool) string {
	var live []sources.Cycle
	for _, c := range cs {
		if !c.Ended(now) && (!ltsOnly || c.LTS || !hasLTS(cs)) {
			live = append(live, c)
		}
	}
	sort.Slice(live, func(i, j int) bool { return less(live[j].Name, live[i].Name) })
	if len(live) == 0 {
		return ""
	}
	return live[0].Name
}

func hasLTS(cs []sources.Cycle) bool {
	for _, c := range cs {
		if c.LTS {
			return true
		}
	}
	return false
}

func fixTag(name, cycle string, variant []string) string {
	if cycle == "" {
		return ""
	}
	return name + ":" + cycle + suffix(variant)
}

func suffix(variant []string) string {
	if len(variant) == 0 {
		return ""
	}
	return "-" + strings.Join(variant, "-")
}

// replaceVariant swaps an end-of-life OS variant for the newest one of its family.
func replaceVariant(tag, old, product string) string {
	repl := map[string]string{"debian": "bookworm", "ubuntu": "noble", "alpine-linux": "alpine"}[product]
	return strings.Replace(tag, old, repl, 1)
}

// precise reports whether ver pins more than the cycle (15.4 vs cycle 15).
func precise(ver, cycle string) bool { return strings.Count(ver, ".") > strings.Count(cycle, ".") }

// less compares dotted numeric versions ("15.4" < "15.10").
func less(a, b string) bool {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < max(len(as), len(bs)); i++ {
		var x, y int
		if i < len(as) {
			x, _ = strconv.Atoi(strings.TrimLeft(as[i], "v"))
		}
		if i < len(bs) {
			y, _ = strconv.Atoi(bs[i])
		}
		if x != y {
			return x < y
		}
	}
	return false
}

func date(c sources.Cycle) string {
	if c.EOL.IsZero() {
		return "—"
	}
	return c.EOL.Format("2006-01-02")
}
