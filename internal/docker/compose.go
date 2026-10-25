package docker

import (
	"path"
	"regexp"
	"strings"

	"github.com/Ali7Zeynalli/depgate/internal/i18n"
	"github.com/Ali7Zeynalli/depgate/internal/report"
)

var dbPorts = map[string]string{
	"5432": "PostgreSQL", "3306": "MySQL", "27017": "MongoDB", "6379": "Redis",
	"9200": "Elasticsearch", "9300": "Elasticsearch", "5672": "RabbitMQ", "15672": "RabbitMQ",
	"11211": "Memcached", "1433": "SQL Server", "26257": "CockroachDB", "8086": "InfluxDB", "9042": "Cassandra",
}

var dangerousCaps = map[string]bool{
	"ALL": true, "SYS_ADMIN": true, "NET_ADMIN": true, "SYS_PTRACE": true, "SYS_MODULE": true, "DAC_READ_SEARCH": true,
}

var hostRootPaths = map[string]bool{
	"/": true, "/etc": true, "/root": true, "/var/run": true, "/proc": true, "/sys": true, "/boot": true, "/dev": true,
}

var healthcheckRe = regexp.MustCompile(`(?m)^\s*(-\s+)?["']?healthcheck["']?\s*:`)

// composeHasHealthcheck is a text check, so it works even on files the
// mini parser rejects.
func composeHasHealthcheck(src string) bool { return healthcheckRe.MatchString(src) }

type composeCtx struct {
	file string
	out  []report.DockerIssue
}

func (c *composeCtx) add(svc string, line int, rule, sev string, title, detail i18n.T, fix string) {
	c.out = append(c.out, report.DockerIssue{File: c.file, Line: line, Service: svc, Rule: rule, Severity: sev, Title: title, Detail: detail, Fix: fix})
}

func truthy(n *yNode) bool {
	switch strings.ToLower(n.str()) {
	case "true", "yes", "on":
		return true
	}
	return false
}

// listOrMap yields the scalar items of a sequence (map items are passed through).
func items(n *yNode) []*yNode {
	if n == nil || n.Kind != ySeq {
		return nil
	}
	return n.Items
}

func checkCompose(file, src string) []report.DockerIssue {
	root, err := parseYAML(src)
	if err != nil || root == nil || root.Kind != yMap {
		return nil
	}
	c := &composeCtx{file: file}
	services := root.get("services")
	var entries []yKey
	if services != nil {
		if services.Kind == yMap {
			entries = services.Keys
		}
	} else {
		for _, e := range root.Keys {
			if e.Val.get("image") != nil || e.Val.get("build") != nil {
				entries = append(entries, e)
			}
		}
	}
	for _, e := range entries {
		if e.Val != nil && e.Val.Kind == yMap {
			c.service(e.Name, e.Val)
		}
	}
	return c.out
}

func (c *composeCtx) service(name string, s *yNode) {
	line := func(k string) int {
		for _, e := range s.Keys {
			if e.Name == k {
				return e.Line
			}
		}
		return s.Line
	}
	if v := s.get("privileged"); truthy(v) {
		c.add(name, line("privileged"), "compose-privileged", "high",
			i18n.F("Konteyner privileged rejimdə işləyir", "Container runs in privileged mode"),
			i18n.F("privileged rejim konteynerə hostun bütün cihazlarına çıxış verir və izolyasiyanı faktiki olaraq ləğv edir.",
				"Privileged mode gives the container all host devices and effectively removes isolation."), "privileged: false")
	}
	if v := s.get("network_mode"); strings.EqualFold(v.str(), "host") {
		c.add(name, line("network_mode"), "compose-host-network", "medium",
			i18n.F("Konteyner hostun şəbəkəsini istifadə edir", "Container uses the host network"),
			i18n.F("`network_mode: host` şəbəkə izolyasiyasını söndürür və bütün portları birbaşa hostda açır.",
				"`network_mode: host` disables network isolation and opens every port directly on the host."), "")
	}
	for _, k := range []string{"pid", "ipc", "userns_mode"} {
		if strings.EqualFold(s.get(k).str(), "host") {
			c.add(name, line(k), "compose-host-namespace", "high",
				i18n.F("`%s: host` host namespace-ni paylaşır", "`%s: host` shares a host namespace", k),
				i18n.F("Konteyner hostun proses və ya yaddaş namespace-ni görür və ona təsir edə bilər.",
					"The container can see and interfere with host processes or memory."), "")
		}
	}
	if u := strings.ToLower(strings.TrimSpace(s.get("user").str())); u == "root" || u == "0" || u == "0:0" || u == "root:root" {
		c.add(name, line("user"), "compose-root-user", "medium",
			i18n.F("Servis root istifadəçisi ilə işləyir", "Service runs as root"),
			i18n.F("Root istifadəçi tətbiqdəki boşluğun təsirini artırır; adi istifadəçi seç.",
				"Running as root magnifies any app bug; pick an unprivileged user."), `user: "10001:10001"`)
	}
	if img := s.get("image"); img != nil && img.Kind == yScalar && s.get("build") == nil && !strings.Contains(img.Value, "$") {
		n, tag, digest := splitImage(img.Value)
		if !digest && (tag == "" || strings.EqualFold(tag, "latest")) && n != "" {
			c.add(name, img.Line, "compose-latest-tag", "medium",
				i18n.F("`%s` image-i sabit versiyasız istifadə olunur", "Image `%s` is not pinned to a version", img.Value),
				i18n.F("`latest` və ya teqsiz image hər `pull`-da dəyişə bilər və xəbərsiz yeniləmə gətirir.",
					"An untagged or `latest` image can change on every pull and bring unreviewed updates."), "image: "+n+":<version>")
		}
	}
	for _, it := range items(s.get("cap_add")) {
		cp := strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(it.str())), "CAP_")
		if dangerousCaps[cp] {
			c.add(name, it.Line, "compose-cap-add", "high",
				i18n.F("Təhlükəli capability əlavə olunur: %s", "Dangerous capability added: %s", cp),
				i18n.F("Bu capability konteynerdən hosta keçməyə imkan verə bilər.",
					"This capability can let a process escape from the container to the host."), "")
		}
	}
	for _, it := range items(s.get("security_opt")) {
		v := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(it.str()), "=", ":"))
		if v == "seccomp:unconfined" || v == "apparmor:unconfined" || v == "label:disable" {
			c.add(name, it.Line, "compose-unconfined", "high",
				i18n.F("Təhlükəsizlik profili söndürülüb (%s)", "Security profile disabled (%s)", it.str()),
				i18n.F("seccomp/AppArmor/SELinux qoruması olmadan konteyner istənilən sistem çağırışını edə bilər.",
					"Without seccomp/AppArmor/SELinux the container can make any system call."), "")
		}
	}
	c.volumes(name, s.get("volumes"))
	c.ports(name, s.get("ports"))
	c.environment(name, s.get("environment"))
}

func (c *composeCtx) volumes(svc string, v *yNode) {
	for _, it := range items(v) {
		var host string
		ro := false
		switch it.Kind {
		case yScalar:
			parts := strings.Split(it.Value, ":")
			if len(parts) < 2 {
				continue
			}
			host = parts[0]
			if len(parts) >= 3 {
				for _, o := range strings.Split(parts[len(parts)-1], ",") {
					if o == "ro" || o == "readonly" {
						ro = true
					}
				}
			}
		case yMap:
			host = it.get("source").str()
			ro = truthy(it.get("read_only"))
		default:
			continue
		}
		if !strings.HasPrefix(host, "/") {
			continue
		}
		clean := path.Clean(host)
		if clean == "/var/run/docker.sock" || clean == "/run/docker.sock" {
			c.add(svc, it.Line, "compose-docker-socket", "high",
				i18n.F("Docker socket konteynerə bağlanır", "Docker socket is mounted into the container"),
				i18n.F("docker.sock-a çıxışı olan konteyner hostda root səlahiyyətinə bərabərdir.",
					"Access to docker.sock is equivalent to root on the host."), "")
			continue
		}
		if hostRootPaths[clean] {
			sev := "high"
			if ro {
				sev = "medium"
			}
			c.add(svc, it.Line, "compose-host-root-mount", sev,
				i18n.F("Hostun sistem qovluğu bağlanır: %s", "Host system path is mounted: %s", clean),
				i18n.F("Hostun həssas qovluğuna çıxış konteynerə hostu oxumağa və ya dəyişməyə imkan verir.",
					"Mounting a sensitive host path lets the container read or change the host."), "")
		}
	}
}

func (c *composeCtx) ports(svc string, v *yNode) {
	for _, it := range items(v) {
		var ip, target string
		switch it.Kind {
		case yScalar:
			ip, target = parsePort(it.Value)
		case yMap:
			target = it.get("target").str()
			ip = it.get("host_ip").str()
		default:
			continue
		}
		target, _, _ = strings.Cut(target, "/")
		db, ok := dbPorts[target]
		if !ok || (ip != "" && ip != "0.0.0.0" && ip != "::" && ip != "[::]") {
			continue
		}
		c.add(svc, it.Line, "compose-db-port-exposed", "high",
			i18n.F("%s portu (%s) bütün şəbəkə interfeyslərində açıqdır", "%s port %s is published on all interfaces", db, target),
			i18n.F("Verilənlər bazası portu internetdən əlçatan ola bilər (Docker firewall-u keçir); onu 127.0.0.1-ə bağla və ya daxili şəbəkədən istifadə et.",
				"The database port can be reachable from the internet (Docker bypasses the firewall); bind it to 127.0.0.1 or use the internal network."),
			`"127.0.0.1:`+target+`:`+target+`"`)
	}
}

// parsePort splits the short port syntax into host IP and container port.
// Ranges return an empty target.
func parsePort(s string) (ip, target string) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end < 0 {
			return "", ""
		}
		ip = s[1:end]
		s = strings.TrimPrefix(s[end+1:], ":")
		parts := strings.Split(s, ":")
		target = parts[len(parts)-1]
	} else {
		parts := strings.Split(s, ":")
		target = parts[len(parts)-1]
		if len(parts) >= 3 {
			ip = strings.Join(parts[:len(parts)-2], ":")
		}
	}
	if strings.Contains(target, "-") {
		return ip, ""
	}
	return ip, target
}

func (c *composeCtx) environment(svc string, v *yNode) {
	if v == nil {
		return
	}
	check := func(key, val string, line int) {
		key = strings.TrimSpace(key)
		if !secretKeyRe.MatchString(key) || !literal(val) {
			return
		}
		c.add(svc, line, "compose-plain-secret", "high",
			i18n.F("`%s` sirri compose faylında açıq yazılıb", "Secret `%s` is written in plain text in the compose file", key),
			i18n.F("Bu fayl adətən git-ə düşür; dəyəri .env faylına və ya Docker secrets-ə köçür.",
				"This file usually lands in git; move the value to a .env file or Docker secrets."), key+": ${"+key+"}")
	}
	switch v.Kind {
	case yMap:
		for _, e := range v.Keys {
			if e.Val != nil && e.Val.Kind == yScalar {
				check(e.Name, e.Val.Value, e.Line)
			}
		}
	case ySeq:
		for _, it := range v.Items {
			if k, val, ok := strings.Cut(it.str(), "="); ok {
				check(k, val, it.Line)
			}
		}
	}
}
