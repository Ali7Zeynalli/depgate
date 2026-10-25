package docker

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Ali7Zeynalli/depgate/internal/i18n"
)

// Compose Specification (https://github.com/compose-spec/compose-spec): the keys
// a compose file may use. Anything else is a typo or an unsupported option that
// Docker Compose rejects or silently ignores.
var topKeys = set("version", "name", "services", "networks", "volumes", "configs", "secrets", "include", "models")

var serviceKeys = set("annotations", "attach", "blkio_config", "build", "cap_add", "cap_drop", "cgroup", "cgroup_parent",
	"command", "configs", "container_name", "cpu_count", "cpu_percent", "cpu_period", "cpu_quota", "cpu_rt_period",
	"cpu_rt_runtime", "cpu_shares", "cpus", "cpuset", "credential_spec", "depends_on", "deploy", "develop",
	"device_cgroup_rules", "devices", "dns", "dns_opt", "dns_search", "domainname", "driver_opts", "entrypoint",
	"env_file", "environment", "expose", "extends", "external_links", "extra_hosts", "gpus", "group_add", "healthcheck",
	"hostname", "image", "init", "ipc", "isolation", "labels", "label_file", "links", "logging", "mac_address",
	"mem_limit", "mem_reservation", "mem_swappiness", "memswap_limit", "models", "network_mode", "networks",
	"oom_kill_disable", "oom_score_adj", "pid", "pids_limit", "platform", "ports", "post_start", "pre_stop",
	"privileged", "profiles", "provider", "pull_policy", "read_only", "restart", "runtime", "scale", "secrets",
	"security_opt", "shm_size", "stdin_open", "stop_grace_period", "stop_signal", "storage_opt", "sysctls", "tmpfs",
	"tty", "ulimits", "use_api_socket", "user", "userns_mode", "uts", "volumes", "volumes_from", "working_dir")

func set(ks ...string) map[string]bool {
	m := map[string]bool{}
	for _, k := range ks {
		m[k] = true
	}
	return m
}

// closest returns the known key within edit distance 2 of k ("" if none).
func closest(k string, known map[string]bool) string {
	best, bd := "", 3
	for c := range known {
		if d := editDistance(k, c); d < bd || d == bd && c < best {
			best, bd = c, d
		}
	}
	return best
}

func editDistance(a, b string) int {
	if a == b {
		return 0
	}
	prev := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur := make([]int, len(b)+1)
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[len(b)]
}

// spec checks a parsed compose file against the Compose Specification and
// common production standards. dir is the compose file's folder ("" skips the
// checks that look at the disk).
func (c *composeCtx) spec(root *yNode, dir string) {
	keyLine := func(n *yNode, k string) int {
		for _, e := range n.Keys {
			if e.Name == k {
				return e.Line
			}
		}
		return n.Line
	}
	if v := root.get("version"); v != nil {
		c.add("", keyLine(root, "version"), "compose-version-obsolete", "low",
			i18n.F("`version` açarı köhnəlib", "The `version` key is obsolete"),
			i18n.F("Compose Specification-da `version` istifadə olunmur; Docker Compose onu nəzərə almır və xəbərdarlıq verir.", "The Compose Specification does not use `version`; Docker Compose ignores it and prints a warning."), "")
	}
	for _, e := range root.Keys {
		if !topKeys[e.Name] && !strings.HasPrefix(e.Name, "x-") && root.get("services") != nil {
			c.unknown("", e.Line, e.Name, topKeys)
		}
	}
	services := root.get("services")
	if services == nil || services.Kind != yMap {
		return
	}
	declared := func(section string) map[string]bool {
		out := map[string]bool{}
		if n := root.get(section); n != nil && n.Kind == yMap {
			for _, e := range n.Keys {
				out[e.Name] = true
			}
		}
		return out
	}
	vols, nets := declared("volumes"), declared("networks")
	names := map[string]*yNode{}
	for _, e := range services.Keys {
		names[e.Name] = e.Val
	}
	var noHealth, noLimit, noRestart []string
	for _, e := range services.Keys {
		svc, s := e.Name, e.Val
		if s == nil || s.Kind != yMap {
			continue
		}
		for _, k := range s.Keys {
			if !serviceKeys[k.Name] && !strings.HasPrefix(k.Name, "x-") {
				c.unknown(svc, k.Line, k.Name, serviceKeys)
			}
		}
		// named volumes must be declared at the top level
		for _, it := range items(s.get("volumes")) {
			src := ""
			switch it.Kind {
			case yScalar:
				if p := strings.Split(it.Value, ":"); len(p) >= 2 {
					src = p[0]
				}
			case yMap:
				if t := it.get("type").str(); t == "" || t == "volume" {
					src = it.get("source").str()
				}
			}
			if src == "" || strings.ContainsAny(src[:1], "/.~$") || strings.Contains(src, "/") || vols[src] {
				continue
			}
			c.add(svc, it.Line, "compose-undefined-volume", "high",
				i18n.F("`%s` volume-u elan olunmayıb", "Volume `%s` is not declared", src),
				i18n.F("Adlı volume yuxarı səviyyədəki `volumes:` bölməsində olmalıdır, yoxsa `docker compose up` xəta verir.", "A named volume must be listed under the top-level `volumes:`, otherwise `docker compose up` fails."),
				"volumes:\n  "+src+":")
		}
		// networks must be declared
		if n := s.get("networks"); n != nil {
			var used []yKey
			if n.Kind == yMap {
				used = n.Keys
			} else {
				for _, it := range items(n) {
					used = append(used, yKey{Name: it.str(), Line: it.Line})
				}
			}
			for _, u := range used {
				if u.Name != "" && u.Name != "default" && !nets[u.Name] {
					c.add(svc, u.Line, "compose-undefined-network", "high",
						i18n.F("`%s` şəbəkəsi elan olunmayıb", "Network `%s` is not declared", u.Name),
						i18n.F("Servisin istifadə etdiyi şəbəkə yuxarı səviyyədəki `networks:` bölməsində olmalıdır.", "A network a service uses must be listed under the top-level `networks:`."), "networks:\n  "+u.Name+":")
				}
			}
		}
		// depends_on: known services, and service_healthy needs a healthcheck
		if d := s.get("depends_on"); d != nil {
			var deps []yKey
			if d.Kind == yMap {
				deps = d.Keys
			} else {
				for _, it := range items(d) {
					deps = append(deps, yKey{Name: it.str(), Line: it.Line})
				}
			}
			for _, dep := range deps {
				target, ok := names[dep.Name]
				if !ok {
					c.add(svc, dep.Line, "compose-unknown-dependency", "high",
						i18n.F("`%s` adlı servis yoxdur", "There is no service named `%s`", dep.Name),
						i18n.F("depends_on mövcud olmayan servisə istinad edir — compose faylı yüklənmir.", "depends_on points at a service that does not exist — the compose file does not load."), "")
					continue
				}
				if dep.Val != nil && dep.Val.get("condition").str() == "service_healthy" && target != nil && target.get("healthcheck") == nil && target.get("build") == nil {
					c.add(svc, dep.Line, "compose-healthy-without-healthcheck", "high",
						i18n.F("`%s` sağlam olmasını gözləyir, amma onun healthcheck-i yoxdur", "Waits for `%s` to be healthy, but it has no healthcheck", dep.Name),
						i18n.F("`condition: service_healthy` üçün hədəf servisdə healthcheck olmalıdır; yoxsa başlama uğursuz olur.", "`condition: service_healthy` needs a healthcheck on the target service, otherwise start-up fails."),
						"healthcheck:\n  test: [\"CMD\", \"pg_isready\"]  # adjust to the service")
				}
			}
		}
		// files referenced from the compose file must exist
		if dir != "" {
			check := func(p string, line int, rule string, what i18n.T) {
				if p == "" || strings.Contains(p, "$") || strings.Contains(p, "://") || strings.HasPrefix(p, "git@") {
					return
				}
				full := p
				if !filepath.IsAbs(p) {
					full = filepath.Join(dir, p)
				}
				if _, err := os.Stat(full); err != nil {
					c.add(svc, line, rule, "medium", what,
						i18n.F("`%s` tapılmadı — `docker compose up` bu servis üçün xəta verəcək.", "`%s` was not found — `docker compose up` fails for this service.", p), "")
				}
			}
			for _, it := range envFiles(s.get("env_file")) {
				check(it.path, it.line, "compose-missing-env-file", i18n.F("env_file faylı yoxdur", "env_file is missing"))
			}
			if b := s.get("build"); b != nil {
				ctx, line := b.str(), b.Line
				if b.Kind == yMap {
					ctx, line = b.get("context").str(), b.Line
					if ctx == "" {
						ctx = "."
					}
				}
				check(ctx, line, "compose-missing-build-context", i18n.F("build qovluğu yoxdur", "Build context is missing"))
			}
		}
		if s.get("links") != nil {
			c.add(svc, keyLine(s, "links"), "compose-links", "low",
				i18n.F("`links` köhnəlmiş seçimdir", "`links` is a legacy option"),
				i18n.F("Eyni şəbəkədəki servislər bir-birini adla tapır; `links` lazım deyil.", "Services on the same network reach each other by name; `links` is not needed."), "")
		}
		long := s.get("ports") != nil || s.get("image") != nil && dbImage(s.get("image").str())
		if long && s.get("healthcheck") == nil && s.get("build") == nil {
			noHealth = append(noHealth, svc)
		}
		if long && s.get("restart") == nil && s.get("deploy").get("restart_policy") == nil {
			noRestart = append(noRestart, svc)
		}
		if s.get("mem_limit") == nil && s.get("deploy").get("resources").get("limits") == nil {
			noLimit = append(noLimit, svc)
		}
	}
	if len(noHealth) > 0 {
		c.add(strings.Join(noHealth, ", "), services.Line, "compose-no-healthcheck", "low",
			i18n.F("Healthcheck yoxdur: %s", "No healthcheck: %s", strings.Join(noHealth, ", ")),
			i18n.F("Healthcheck olmadan Docker donmuş servisi işlək sayır və depends_on onun hazır olmasını gözləyə bilmir.", "Without a healthcheck Docker treats a hung service as running and depends_on cannot wait for it to be ready."), "")
	}
	if len(noRestart) > 0 {
		c.add(strings.Join(noRestart, ", "), services.Line, "compose-no-restart", "low",
			i18n.F("Restart siyasəti yoxdur: %s", "No restart policy: %s", strings.Join(noRestart, ", ")),
			i18n.F("Server yenidən başlayanda və ya proses çökəndə bu servislər özü qalxmır.", "These services do not come back after a crash or a host reboot."), "restart: unless-stopped")
	}
	if len(noLimit) > 0 {
		sort.Strings(noLimit)
		c.add(strings.Join(noLimit, ", "), services.Line, "compose-no-memory-limit", "low",
			i18n.F("Yaddaş limiti yoxdur: %s", "No memory limit: %s", strings.Join(noLimit, ", ")),
			i18n.F("Limitsiz servis yaddaş sızmasında bütün hostu dondura bilər.", "A service without a limit can take the whole host down with a memory leak."), "mem_limit: 512m")
	}
}

func (c *composeCtx) unknown(svc string, line int, key string, known map[string]bool) {
	fix := ""
	msg := i18n.F("Compose Specification-da `%s` açarı yoxdur; Docker Compose onu rədd edir və ya nəzərə almır.", "`%s` is not a Compose Specification key; Docker Compose rejects or ignores it.", key)
	if s := closest(key, known); s != "" {
		fix = s + ":"
		msg = i18n.F("`%s` açarı yoxdur — yəqin `%s` nəzərdə tutulub.", "`%s` is not a valid key — probably `%s`.", key, s)
	}
	c.add(svc, line, "compose-unknown-key", "medium", i18n.F("Bilinməyən açar: `%s`", "Unknown key: `%s`", key), msg, fix)
}

type envRef struct {
	path string
	line int
}

func envFiles(n *yNode) []envRef {
	if n == nil {
		return nil
	}
	if n.Kind == yScalar {
		return []envRef{{n.Value, n.Line}}
	}
	var out []envRef
	for _, it := range items(n) {
		switch it.Kind {
		case yScalar:
			out = append(out, envRef{it.Value, it.Line})
		case yMap:
			if r := it.get("required"); r != nil && !truthy(r) {
				continue // optional env file
			}
			out = append(out, envRef{it.get("path").str(), it.Line})
		}
	}
	return out
}

func dbImage(ref string) bool {
	name, _, _ := splitImage(strings.ToLower(ref))
	name = name[strings.LastIndex(name, "/")+1:]
	switch name {
	case "postgres", "postgresql", "mysql", "mariadb", "mongo", "mongodb", "redis", "valkey", "elasticsearch", "opensearch", "rabbitmq", "memcached", "clickhouse-server", "minio":
		return true
	}
	return false
}
