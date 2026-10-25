package docker

import (
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Ali7Zeynalli/depgate/internal/report"
)

func writeFiles(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, body := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func checkTexts(t *testing.T, is []report.DockerIssue) {
	t.Helper()
	for _, i := range is {
		if i.Title.Az == "" || i.Title.En == "" || i.Detail.Az == "" || i.Detail.En == "" {
			t.Errorf("issue %s has empty text: %+v", i.Rule, i)
		}
		if i.Severity != "high" && i.Severity != "medium" && i.Severity != "low" {
			t.Errorf("issue %s bad severity %q", i.Rule, i.Severity)
		}
		if i.File == "" || i.Line <= 0 {
			t.Errorf("issue %s missing file/line: %+v", i.Rule, i)
		}
	}
}

func find(is []report.DockerIssue, rule string) []report.DockerIssue {
	var out []report.DockerIssue
	for _, i := range is {
		if i.Rule == rule {
			out = append(out, i)
		}
	}
	return out
}

// good is a Dockerfile that triggers no rules on its own.
const good = "FROM node:22-bookworm-slim\nWORKDIR /app\nCOPY package*.json ./\nRUN npm ci --ignore-scripts\nCOPY src ./src\nUSER node\nHEALTHCHECK CMD node -e 1\nCMD [\"node\",\"src/index.js\"]\n"

func TestDockerfileRules(t *testing.T) {
	cases := []struct {
		name string
		df   string
		rule string
		want int // expected number of issues with rule
		sev  string
		fix  string
		line int
	}{
		{"good file clean", good, "", 0, "", "", 0},
		{"latest tag", "FROM node:latest\nUSER node\n", "dockerfile-latest-tag", 1, "medium", "FROM node:22-bookworm-slim", 1},
		{"no tag other image", "FROM python\nUSER 1000\n", "dockerfile-latest-tag", 1, "medium", "FROM python:<version>", 1},
		{"no tag with stage name", "FROM node AS build\nUSER node\n", "dockerfile-latest-tag", 1, "", "FROM node:22-bookworm-slim AS build", 0},
		{"pinned tag ok", "FROM node:22\nUSER node\n", "dockerfile-latest-tag", 0, "", "", 0},
		{"digest ok", "FROM node@sha256:abcd\nUSER node\n", "dockerfile-latest-tag", 0, "", "", 0},
		{"scratch and stage ref ok", "FROM golang:1.24 AS build\nFROM build\nFROM scratch\n", "dockerfile-latest-tag", 0, "", "", 0},
		{"registry port no tag", "FROM localhost:5000/app\nUSER 1\n", "dockerfile-latest-tag", 1, "", "", 0},
		{"lower-case from", "from node\nuser node\n", "dockerfile-latest-tag", 1, "", "", 0},

		{"no user", "FROM node:22\nCMD node\n", "dockerfile-root-user", 1, "high", "USER node", 1},
		{"root user", "FROM debian:12\nUSER root\nRUN x\n", "dockerfile-root-user", 1, "high", "USER 10001", 2},
		{"user 0:0", "FROM debian:12\nUSER 0:0\n", "dockerfile-root-user", 1, "", "", 0},
		{"user switched back", "FROM node:22\nUSER root\nRUN x\nUSER node\n", "dockerfile-root-user", 0, "", "", 0},
		{"distroless nonroot", "FROM node:22 AS b\nRUN npm ci --ignore-scripts\nFROM gcr.io/distroless/nodejs22-debian12:nonroot\n", "dockerfile-root-user", 0, "", "", 0},
		{"scratch final", "FROM golang:1.24 AS b\nFROM scratch\n", "dockerfile-root-user", 0, "", "", 0},
		{"only final stage", "FROM node:22 AS b\nRUN x\nFROM node:22-slim\nUSER node\n", "dockerfile-root-user", 0, "", "", 0},
		{"user inherited from stage", "FROM node:22 AS base\nUSER node\nFROM base\nCMD x\n", "dockerfile-root-user", 0, "", "", 0},
		{"node fix via stage", "FROM node:22 AS base\nFROM base\n", "dockerfile-root-user", 1, "", "USER node", 0},

		{"secret env new form", "FROM node:22\nENV A=1 DB_PASSWORD=hunter2\n", "dockerfile-secret-env", 1, "high", "", 2},
		{"secret env legacy", "FROM node:22\nENV API_KEY abc def\n", "dockerfile-secret-env", 1, "high", "", 2},
		{"secret arg literal", "FROM node:22\nARG NPM_TOKEN=abc\n", "dockerfile-secret-env", 1, "high", "", 0},
		{"secret env var ref", "FROM node:22\nARG NPM_TOKEN\nENV NPM_TOKEN=$NPM_TOKEN X_SECRET=${S}\n", "dockerfile-secret-env", 0, "", "", 0},
		{"secret env empty", "FROM node:22\nENV SECRET_KEY=\"\"\n", "dockerfile-secret-env", 0, "", "", 0},
		{"non-secret env", "FROM node:22\nENV NODE_ENV=production\n", "dockerfile-secret-env", 0, "", "", 0},
		{"secret arg", "FROM node:22\nARG NPM_TOKEN\n", "dockerfile-secret-arg", 1, "medium", "RUN --mount=type=secret,id=npm_token,env=NPM_TOKEN <command>", 2},
		{"arg non-secret", "FROM node:22\nARG VERSION\n", "dockerfile-secret-arg", 0, "", "", 0},

		{"npm install", "FROM node:22\nRUN npm install\n", "dockerfile-npm-install", 1, "medium", "RUN npm ci", 2},
		{"npm i", "FROM node:22\nRUN cd /app && npm i --omit=dev\n", "dockerfile-npm-install", 1, "", "", 0},
		{"npm install -g", "FROM node:22\nRUN npm install -g pnpm\n", "dockerfile-npm-install", 0, "", "", 0},
		{"npm ci ok", "FROM node:22\nRUN npm ci\n", "dockerfile-npm-install", 0, "", "", 0},
		{"yarn bare", "FROM node:22\nRUN yarn\n", "dockerfile-npm-install", 1, "", "RUN yarn install --immutable", 0},
		{"yarn frozen ok", "FROM node:22\nRUN yarn install --frozen-lockfile\n", "dockerfile-npm-install", 0, "", "", 0},
		{"yarn build not install", "FROM node:22\nRUN yarn build\n", "dockerfile-npm-install", 0, "", "", 0},
		{"pnpm install", "FROM node:22\nRUN pnpm install\n", "dockerfile-npm-install", 1, "", "RUN pnpm install --frozen-lockfile", 0},
		{"pnpm frozen ok", "FROM node:22\nRUN pnpm install --frozen-lockfile --ignore-scripts\n", "dockerfile-npm-install", 0, "", "", 0},
		{"continuation", "FROM node:22\nRUN apt-get update \\\n  # comment\n  && npm install\n", "dockerfile-npm-install", 1, "", "", 2},
		{"exec form", "FROM node:22\nRUN [\"npm\", \"install\"]\n", "dockerfile-npm-install", 1, "", "", 0},

		{"install scripts", "FROM node:22\nRUN npm ci\n", "dockerfile-install-scripts", 1, "low", "RUN npm ci --ignore-scripts", 2},
		{"bun install scripts", "FROM oven/bun:1\nRUN bun install\n", "dockerfile-install-scripts", 1, "", "RUN bun install --ignore-scripts", 0},
		{"ignore scripts ok", "FROM node:22\nRUN npm ci --ignore-scripts\n", "dockerfile-install-scripts", 0, "", "", 0},
		{"global no scripts issue", "FROM node:22\nRUN npm i -g pnpm\n", "dockerfile-install-scripts", 0, "", "", 0},

		{"curl sh", "FROM debian:12\nRUN curl -fsSL https://x.sh | sh\n", "dockerfile-curl-pipe", 1, "high", "", 2},
		{"wget sudo bash", "FROM debian:12\nRUN wget -qO- https://x | sudo -E bash -\n", "dockerfile-curl-pipe", 1, "", "", 0},
		{"bash process subst", "FROM debian:12\nRUN bash <(curl -s https://x)\n", "dockerfile-curl-pipe", 1, "", "", 0},
		{"curl to file ok", "FROM debian:12\nRUN curl -fsSLo /tmp/x https://x && sha256sum -c sums\n", "dockerfile-curl-pipe", 0, "", "", 0},
		{"curl pipe tar ok", "FROM debian:12\nRUN curl -L https://x.tgz | tar xz\n", "dockerfile-curl-pipe", 0, "", "", 0},

		{"add url", "FROM debian:12\nADD https://example.com/a.bin /a.bin\n", "dockerfile-add-url", 1, "medium", "", 2},
		{"add url checksum ok", "FROM debian:12\nADD --checksum=sha256:aa https://example.com/a.bin /a.bin\n", "dockerfile-add-url", 0, "", "", 0},
		{"add local", "FROM debian:12\nADD src /app/src\n", "dockerfile-add-local", 1, "low", "COPY src /app/src", 2},
		{"add archive ok", "FROM debian:12\nADD rootfs.tar.gz /\n", "dockerfile-add-local", 0, "", "", 0},

		{"no healthcheck", "FROM node:22\nUSER node\n", "dockerfile-no-healthcheck", 1, "low", "", 1},
		{"healthcheck ok", "FROM node:22\nHEALTHCHECK NONE\n", "dockerfile-no-healthcheck", 0, "", "", 0},

		{"ssh port", "FROM debian:12\nEXPOSE 80 22/tcp\n", "dockerfile-ssh-port", 1, "medium", "", 2},
		{"other port ok", "FROM debian:12\nEXPOSE 3000 2222\n", "dockerfile-ssh-port", 0, "", "", 0},

		{"sudo", "FROM debian:12\nRUN sudo apt-get update\n", "dockerfile-sudo", 1, "low", "", 2},
		{"no sudo", "FROM debian:12\nRUN apt-get update\n", "dockerfile-sudo", 0, "", "", 0},

		{"apt recommends once", "FROM debian:12\nRUN apt-get install -y curl\nRUN apt-get install -y git\n", "dockerfile-apt-recommends", 1, "low", "RUN apt-get install --no-install-recommends -y curl", 2},
		{"apt no-recommends ok", "FROM debian:12\nRUN apt-get update && apt-get install -y --no-install-recommends curl\n", "dockerfile-apt-recommends", 0, "", "", 0},
		{"heredoc", "FROM debian:12\nRUN <<EOF\napt-get update\nUSER root\nEOF\nUSER 1000\n", "dockerfile-root-user", 0, "", "", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeFiles(t, dir, map[string]string{"Dockerfile": tc.df, ".dockerignore": ".env*\nnode_modules\n"})
			is, files := Scan(dir, "")
			checkTexts(t, is)
			if len(files) != 1 || files[0] != "Dockerfile" {
				t.Fatalf("files = %v", files)
			}
			if tc.rule == "" {
				if len(is) != 0 {
					t.Fatalf("want no issues, got %+v", is)
				}
				return
			}
			got := find(is, tc.rule)
			if len(got) != tc.want {
				t.Fatalf("rule %s: got %d issues, want %d: %+v", tc.rule, len(got), tc.want, is)
			}
			if tc.want == 0 {
				return
			}
			g := got[0]
			if tc.sev != "" && g.Severity != tc.sev {
				t.Errorf("severity %s, want %s", g.Severity, tc.sev)
			}
			if tc.fix != "" && g.Fix != tc.fix {
				t.Errorf("fix %q, want %q", g.Fix, tc.fix)
			}
			if tc.line != 0 && g.Line != tc.line {
				t.Errorf("line %d, want %d", g.Line, tc.line)
			}
		})
	}
}

func TestDockerignore(t *testing.T) {
	df := "FROM node:22\nUSER node\nCOPY . .\n"
	cases := []struct {
		name   string
		ignore *string
		want   int
		detail string
	}{
		{"missing file", nil, 1, "no `.dockerignore`"},
		{"no env entry", ptr("node_modules\n"), 1, "does not list `.env`, so"},
		{"no env nor node_modules", ptr("dist\n"), 1, "`.env` or node_modules"},
		{"env star", ptr(".env*\nnode_modules\n"), 0, ""},
		{"star env", ptr("*.env\n"), 0, ""},
		{"globstar env", ptr("**/.env\n"), 0, ""},
		{"negated env", ptr(".env\n!.env\n"), 1, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			files := map[string]string{"Dockerfile": df}
			if tc.ignore != nil {
				files[".dockerignore"] = *tc.ignore
			}
			writeFiles(t, dir, files)
			is, _ := Scan(dir, dir)
			got := find(is, "dockerfile-dockerignore")
			if len(got) != tc.want {
				t.Fatalf("got %d, want %d: %+v", len(got), tc.want, is)
			}
			if tc.detail != "" && !strings.Contains(got[0].Detail.En, tc.detail) {
				t.Errorf("detail %q lacks %q", got[0].Detail.En, tc.detail)
			}
			if tc.want == 1 && got[0].Line != 3 {
				t.Errorf("line %d", got[0].Line)
			}
		})
	}
	// COPY --from=build . . does not use the build context
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{"Dockerfile": "FROM node:22 AS b\nFROM node:22\nCOPY --from=b . .\nUSER node\n"})
	is, _ := Scan(dir, "")
	if n := len(find(is, "dockerfile-dockerignore")); n != 0 {
		t.Errorf("COPY --from flagged: %+v", is)
	}
}

func ptr(s string) *string { return &s }

func TestComposeRules(t *testing.T) {
	cases := []struct {
		name    string
		yml     string
		rule    string
		want    int
		sev     string
		line    int
		service string
		fix     string
	}{
		{"privileged", "services:\n  app:\n    image: nginx:1.27\n    privileged: true\n", "compose-privileged", 1, "high", 4, "app", ""},
		{"privileged false", "services:\n  app:\n    image: nginx:1.27\n    privileged: false\n", "compose-privileged", 0, "", 0, "", ""},
		{"docker sock short", "services:\n  agent:\n    image: x:1\n    volumes:\n      - \"/var/run/docker.sock:/var/run/docker.sock\"\n", "compose-docker-socket", 1, "high", 5, "agent", ""},
		{"docker sock long", "services:\n  agent:\n    image: x:1\n    volumes:\n      - type: bind\n        source: /run/docker.sock\n        target: /var/run/docker.sock\n", "compose-docker-socket", 1, "high", 5, "", ""},
		{"named volume ok", "services:\n  db:\n    image: postgres:16\n    volumes:\n      - pgdata:/var/lib/postgresql/data\n", "compose-docker-socket", 0, "", 0, "", ""},
		{"db port quoted", "services:\n  db:\n    image: postgres:16\n    ports:\n      - \"5432:5432\"\n", "compose-db-port-exposed", 1, "high", 5, "db", `"127.0.0.1:5432:5432"`},
		{"db port plain", "services:\n  db:\n    image: redis:7\n    ports:\n      - 6380:6379\n", "compose-db-port-exposed", 1, "", 0, "", `"127.0.0.1:6379:6379"`},
		{"db port all ifaces", "services:\n  db:\n    image: mysql:8\n    ports: [\"0.0.0.0:3306:3306\"]\n", "compose-db-port-exposed", 1, "", 4, "", ""},
		{"db port container only", "services:\n  db:\n    image: mongo:7\n    ports:\n      - \"27017\"\n", "compose-db-port-exposed", 1, "", 0, "", ""},
		{"db port ipv6", "services:\n  db:\n    image: postgres:16\n    ports:\n      - \"[::]:5432:5432/tcp\"\n", "compose-db-port-exposed", 1, "", 0, "", ""},
		{"db port long", "services:\n  db:\n    image: postgres:16\n    ports:\n      - target: 5432\n        published: 5432\n", "compose-db-port-exposed", 1, "", 5, "", ""},
		{"db port localhost ok", "services:\n  db:\n    image: postgres:16\n    ports:\n      - \"127.0.0.1:5432:5432\"\n      - target: 5432\n        host_ip: 127.0.0.1\n", "compose-db-port-exposed", 0, "", 0, "", ""},
		{"db port host side only ok", "services:\n  web:\n    image: app:1\n    ports:\n      - \"5432:3000\"\n      - \"5000-5010:5000-5010\"\n", "compose-db-port-exposed", 0, "", 0, "", ""},
		{"host network", "services:\n  app:\n    image: x:1\n    network_mode: host\n", "compose-host-network", 1, "medium", 4, "", ""},
		{"bridge ok", "services:\n  app:\n    image: x:1\n    network_mode: bridge\n", "compose-host-network", 0, "", 0, "", ""},
		{"plain secret map", "services:\n  api:\n    image: x:1\n    environment:\n      NODE_ENV: production\n      DB_PASSWORD: hunter2\n", "compose-plain-secret", 1, "high", 6, "api", "DB_PASSWORD: ${DB_PASSWORD}"},
		{"plain secret list", "services:\n  api:\n    image: x:1\n    environment:\n      - JWT_SECRET=abc123\n", "compose-plain-secret", 1, "", 5, "", ""},
		{"secret from env ok", "services:\n  api:\n    image: x:1\n    environment:\n      DB_PASSWORD: ${DB_PASSWORD}\n      - \n", "compose-plain-secret", 0, "", 0, "", ""},
		{"secret refs ok", "services:\n  api:\n    image: x:1\n    environment:\n      DB_PASSWORD: ${DB_PASSWORD}\n      API_TOKEN: $API_TOKEN\n      EMPTY_SECRET: \"\"\n      NULL_TOKEN:\n", "compose-plain-secret", 0, "", 0, "", ""},
		{"latest tag", "services:\n  web:\n    image: nginx\n  web2:\n    image: nginx:latest\n", "compose-latest-tag", 2, "medium", 3, "web", "image: nginx:<version>"},
		{"tag with build ok", "services:\n  web:\n    build: .\n    image: myapp\n  db:\n    image: postgres@sha256:abc\n", "compose-latest-tag", 0, "", 0, "", ""},
		{"cap add", "services:\n  app:\n    image: x:1\n    cap_add:\n      - NET_BIND_SERVICE\n      - SYS_ADMIN\n      - CAP_NET_ADMIN\n", "compose-cap-add", 2, "high", 6, "", ""},
		{"cap add harmless", "services:\n  app:\n    image: x:1\n    cap_add: [NET_BIND_SERVICE, CHOWN]\n", "compose-cap-add", 0, "", 0, "", ""},
		{"host namespaces", "services:\n  app:\n    image: x:1\n    pid: host\n    ipc: host\n    userns_mode: \"host\"\n", "compose-host-namespace", 3, "high", 4, "", ""},
		{"pid service ok", "services:\n  app:\n    image: x:1\n    pid: \"service:db\"\n", "compose-host-namespace", 0, "", 0, "", ""},
		{"unconfined", "services:\n  app:\n    image: x:1\n    security_opt:\n      - seccomp:unconfined\n      - apparmor=unconfined\n      - label:disable\n      - no-new-privileges:true\n", "compose-unconfined", 3, "high", 5, "", ""},
		{"host root mount", "services:\n  app:\n    image: x:1\n    volumes:\n      - /:/host\n      - /etc:/etc:ro\n      - /etc/localtime:/etc/localtime:ro\n      - ./data:/data\n", "compose-host-root-mount", 2, "high", 5, "", ""},
		{"user root", "services:\n  app:\n    image: x:1\n    user: root\n  b:\n    image: x:1\n    user: \"0:0\"\n", "compose-root-user", 2, "medium", 4, "app", ""},
		{"user nonroot ok", "services:\n  app:\n    image: x:1\n    user: \"1000:1000\"\n", "compose-root-user", 0, "", 0, "", ""},
		{"legacy v1", "db:\n  image: postgres\n  ports:\n    - \"5432:5432\"\nversion_note: x\n", "compose-db-port-exposed", 1, "", 4, "db", ""},
		{"broken yaml skipped", "services:\n  app:\n   image: x\n  privileged: true\n    bad: [\n", "compose-privileged", 0, "", 0, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeFiles(t, dir, map[string]string{"docker-compose.yml": tc.yml})
			is, files := Scan(dir, "")
			checkTexts(t, is)
			if len(files) != 1 || files[0] != "docker-compose.yml" {
				t.Fatalf("files = %v", files)
			}
			got := find(is, tc.rule)
			if len(got) != tc.want {
				t.Fatalf("rule %s: got %d, want %d: %+v", tc.rule, len(got), tc.want, is)
			}
			if tc.want == 0 {
				return
			}
			g := got[0]
			if tc.sev != "" && g.Severity != tc.sev {
				t.Errorf("severity %s, want %s", g.Severity, tc.sev)
			}
			if tc.line != 0 && g.Line != tc.line {
				t.Errorf("line %d, want %d", g.Line, tc.line)
			}
			if tc.service != "" && g.Service != tc.service {
				t.Errorf("service %q, want %q", g.Service, tc.service)
			}
			if tc.fix != "" && g.Fix != tc.fix {
				t.Errorf("fix %q, want %q", g.Fix, tc.fix)
			}
		})
	}
}

func TestHostRootMountReadOnlyIsMedium(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{"compose.yaml": "services:\n  a:\n    image: x:1\n    volumes:\n      - /proc:/host/proc:ro\n      - type: bind\n        source: /sys\n        target: /s\n        read_only: true\n"})
	is, _ := Scan(dir, "")
	got := find(is, "compose-host-root-mount")
	if len(got) != 2 || got[0].Severity != "medium" || got[1].Severity != "medium" {
		t.Fatalf("got %+v", got)
	}
}

func TestPlainSecretValueNotLeaked(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{"docker-compose.yml": "services:\n  a:\n    image: x:1\n    environment:\n      DB_PASSWORD: s3cr3tvalue\n",
		"Dockerfile": "FROM node:22\nENV API_KEY=s3cr3tvalue\n"})
	is, _ := Scan(dir, "")
	for _, i := range is {
		for _, s := range []string{i.Title.Az, i.Title.En, i.Detail.Az, i.Detail.En, i.Fix} {
			if strings.Contains(s, "s3cr3tvalue") {
				t.Fatalf("secret value leaked in %s: %q", i.Rule, s)
			}
		}
	}
}

func TestHealthcheckInComposeSuppressesDockerfileRule(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{
		"Dockerfile":         "FROM node:22\nUSER node\n",
		"docker-compose.yml": "services:\n  app:\n    build: .\n    healthcheck:\n      test: [\"CMD\", \"true\"]\n",
	})
	is, _ := Scan(dir, "")
	if n := len(find(is, "dockerfile-no-healthcheck")); n != 0 {
		t.Fatalf("healthcheck rule fired: %+v", is)
	}
}

func TestMonorepo(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"docker-compose.yml":            "services:\n  db:\n    image: postgres:16\n    ports:\n      - \"5432:5432\"\n",
		"apps/api/Dockerfile":           "FROM node:22\nCMD node\n",
		"apps/api/Dockerfile.dev":       good,
		"apps/api/node_modules/x.yml":   "services: {}\n",
		"apps/api/compose.prod.yaml":    "services:\n  a:\n    image: x:1\n",
		"apps/api/notes.yml":            "services:\n  a:\n    privileged: true\n",
		"apps/api/web.Dockerfile":       good,
		"apps/api/sub/Dockerfile":       "FROM node\n",
		"apps/api/.dockerignore":        ".env\nnode_modules\n",
		"apps/api/docker-compose.x.yml": "services:\n  b:\n    image: y:2\n",
	})
	dir := filepath.Join(root, "apps", "api")
	is, files := Scan(dir, root)
	want := []string{"../../docker-compose.yml", "Dockerfile", "Dockerfile.dev", "compose.prod.yaml", "docker-compose.x.yml", "web.Dockerfile"}
	if strings.Join(files, ",") != strings.Join(want, ",") {
		t.Fatalf("files = %v, want %v", files, want)
	}
	db := find(is, "compose-db-port-exposed")
	if len(db) != 1 || db[0].File != "../../docker-compose.yml" || db[0].Service != "db" {
		t.Fatalf("db issue = %+v", db)
	}
	// sorted: high first, then file, then line
	for i := 1; i < len(is); i++ {
		a, b := is[i-1], is[i]
		if sevRank[a.Severity] > sevRank[b.Severity] ||
			(a.Severity == b.Severity && (a.File > b.File || (a.File == b.File && a.Line > b.Line))) {
			t.Fatalf("not sorted at %d: %+v / %+v", i, a, b)
		}
	}
	// same dir passed twice is not duplicated
	_, files2 := Scan(dir, dir)
	if len(files2) != 5 {
		t.Fatalf("files2 = %v", files2)
	}
}

func TestParseYAML(t *testing.T) {
	src := `---
# top comment
x-common: &common
  restart: unless-stopped
  logging: { driver: "json-file", options: {max-size: 10m} }
services:
  web:
    <<: *common
    image: "nginx:1.27" # pinned
    command: "echo '#not a comment'"
    label: 'it''s # here'
    ports: [ "80:80", 443 ]
    entrypoint: |
      #!/bin/sh
      key: not-a-key
        - not a list
    depends_on:
      - db
      - cache
    deploy:
      resources:
        limits: {cpus: "0.5"}
    healthcheck:
      test:
        - CMD
        - curl
    volumes:
    - type: bind
      source: ./a
      target: /a
    - ./b:/b
    env: *common
  db:
    image: postgres:16
...
ignored: true
`
	root, err := parseYAML(src)
	if err != nil {
		t.Fatal(err)
	}
	web := root.get("services").get("web")
	if web == nil {
		t.Fatal("no web")
	}
	if got := web.get("image"); got.str() != "nginx:1.27" || got.Line != 9 {
		t.Errorf("image = %+v", got)
	}
	if got := web.get("command").str(); got != "echo '#not a comment'" {
		t.Errorf("command = %q", got)
	}
	if got := web.get("label").str(); got != "it's # here" {
		t.Errorf("label = %q", got)
	}
	ports := web.get("ports")
	if ports.Kind != ySeq || len(ports.Items) != 2 || ports.Items[0].str() != "80:80" || ports.Items[1].str() != "443" {
		t.Errorf("ports = %+v", ports)
	}
	if web.get("entrypoint").Kind != yScalar {
		t.Errorf("entrypoint not skipped")
	}
	if d := web.get("depends_on"); len(d.Items) != 2 || d.Items[1].str() != "cache" {
		t.Errorf("depends_on = %+v", d)
	}
	if got := web.get("deploy").get("resources").get("limits").get("cpus").str(); got != "0.5" {
		t.Errorf("cpus = %q", got)
	}
	vols := web.get("volumes")
	if len(vols.Items) != 2 || vols.Items[0].get("source").str() != "./a" || vols.Items[0].get("target").Line != 30 || vols.Items[1].str() != "./b:/b" {
		t.Errorf("volumes = %+v", vols)
	}
	if web.get("env").Kind != yAlias {
		t.Errorf("alias kind = %v", web.get("env").Kind)
	}
	if web.get("<<") != nil {
		t.Errorf("merge key kept")
	}
	if root.get("services").get("db").get("image").str() != "postgres:16" {
		t.Errorf("db image")
	}
	if root.get("ignored") != nil {
		t.Errorf("second document parsed")
	}
	if got := root.get("x-common").get("logging").get("options").get("max-size").str(); got != "10m" {
		t.Errorf("flow map = %q", got)
	}
}

func TestParseYAMLErrors(t *testing.T) {
	for _, src := range []string{
		"a:\n   b: 1\n  c: 2\n",
		"a: [1, 2\n",
		"a: \"unterminated\n",
		"just text\nmore: x\n",
		"? complex\n: key\n",
	} {
		if _, err := parseYAML(src); err == nil {
			t.Errorf("expected error for %q", src)
		}
	}
	for _, src := range []string{"", "# only comment\n", "---\n", "a:\n", "- a\n- b\n", "a: 'x'\n"} {
		if _, err := parseYAML(src); err != nil {
			t.Errorf("unexpected error for %q: %v", src, err)
		}
	}
}

func TestGarbageDoesNotPanic(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	alphabet := []byte(" \t\n\n\n-:#'\"[]{},&*<|>!\\=$@/.abcFROMRUNUSERservicesimageports0123456789")
	seeds := []string{
		"services:\n  a:\n    image: x\n    ports: [\"5432:5432\"]\n    environment:\n      - A_TOKEN=1\n",
		"FROM node AS a\nRUN npm install && curl x | sh\nUSER root\nCOPY . .\nADD http://x /y\nENV A_SECRET x\n",
	}
	for i := 0; i < 3000; i++ {
		var b []byte
		if i%3 == 0 {
			b = []byte(seeds[i%2])
			for j := 0; j < 1+r.Intn(8); j++ {
				p := r.Intn(len(b) + 1)
				b = append(b[:p], append([]byte{alphabet[r.Intn(len(alphabet))]}, b[p:]...)...)
			}
		} else {
			n := r.Intn(200)
			b = make([]byte, n)
			for j := range b {
				b[j] = alphabet[r.Intn(len(alphabet))]
			}
		}
		s := string(b)
		func() {
			defer func() {
				if p := recover(); p != nil {
					t.Fatalf("panic on %q: %v", s, p)
				}
			}()
			_, _ = parseYAML(s)
			checkCompose("c.yml", s)
			checkDockerfile(&dfCtx{file: "Dockerfile", path: filepath.Join(t.TempDir(), "Dockerfile"), src: s})
		}()
	}
}
