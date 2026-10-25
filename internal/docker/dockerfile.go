package docker

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Ali7Zeynalli/depgate/internal/i18n"
	"github.com/Ali7Zeynalli/depgate/internal/report"
)

// instr is one logical Dockerfile instruction.
type instr struct {
	Cmd  string // upper-case instruction name
	Args string // everything after the name, continuations joined
	Line int    // line where the instruction starts
}

type stage struct {
	Image string // FROM image reference
	Name  string // AS name (lower-case), may be ""
	Line  int
	Body  []instr
	Base  *stage // earlier stage this one builds FROM, if any
}

var heredocRe = regexp.MustCompile(`<<-?\s*["']?([A-Za-z_][A-Za-z0-9_]*)["']?`)

// parseDockerfile splits src into instructions. It never fails; unknown
// lines are kept as instructions and ignored by the rules.
func parseDockerfile(src string) []instr {
	lines := strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n")
	var out []instr
	for i := 0; i < len(lines); i++ {
		t := strings.TrimSpace(lines[i])
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		start := i + 1
		var b strings.Builder
		for {
			t = strings.TrimRight(lines[i], " \t")
			if strings.HasSuffix(t, "\\") && i+1 < len(lines) {
				b.WriteString(strings.TrimSuffix(t, "\\"))
				b.WriteByte(' ')
				i++
				// comments and blank lines inside a continuation are dropped
				for i+1 < len(lines) {
					nt := strings.TrimSpace(lines[i])
					if nt != "" && !strings.HasPrefix(nt, "#") {
						break
					}
					i++
				}
				continue
			}
			b.WriteString(strings.TrimSuffix(t, "\\"))
			break
		}
		full := strings.TrimSpace(b.String())
		// heredoc bodies (RUN <<EOF ... EOF) belong to the instruction
		if m := heredocRe.FindStringSubmatch(full); m != nil {
			for i+1 < len(lines) {
				i++
				if strings.TrimSpace(lines[i]) == m[1] {
					break
				}
				full += "\n" + lines[i]
			}
		}
		cmd, args := full, ""
		if j := strings.IndexAny(full, " \t"); j >= 0 {
			cmd, args = full[:j], strings.TrimSpace(full[j+1:])
		}
		out = append(out, instr{Cmd: strings.ToUpper(cmd), Args: args, Line: start})
	}
	return out
}

// stages groups instructions by FROM. Instructions before the first FROM
// (ARG) are dropped.
func stages(ins []instr) []*stage {
	var out []*stage
	byName := map[string]*stage{}
	for _, in := range ins {
		if in.Cmd == "FROM" {
			f := words(in.Args)
			var rest []string
			for _, w := range f {
				if !strings.HasPrefix(w, "--") {
					rest = append(rest, w)
				}
			}
			st := &stage{Line: in.Line}
			if len(rest) > 0 {
				st.Image = rest[0]
			}
			if len(rest) >= 3 && strings.EqualFold(rest[1], "as") {
				st.Name = strings.ToLower(rest[2])
			}
			st.Base = byName[strings.ToLower(st.Image)]
			if st.Name != "" {
				byName[st.Name] = st
			}
			out = append(out, st)
			continue
		}
		if len(out) > 0 {
			out[len(out)-1].Body = append(out[len(out)-1].Body, in)
		}
	}
	return out
}

// rootImage follows FROM <stage> links to the external image.
func (s *stage) rootImage() string {
	for n := 0; s.Base != nil && n < 64; n++ {
		s = s.Base
	}
	return s.Image
}

// last returns the last instruction named cmd in s or the stages it builds on.
func (s *stage) last(cmd string) *instr {
	for n := 0; s != nil && n < 64; n++ {
		for i := len(s.Body) - 1; i >= 0; i-- {
			if s.Body[i].Cmd == cmd {
				return &s.Body[i]
			}
		}
		s = s.Base
	}
	return nil
}

// words splits shell-like text on whitespace, honouring quotes.
func words(s string) []string {
	var out []string
	var b strings.Builder
	var q rune
	in := false
	esc := false
	for _, r := range s {
		switch {
		case esc:
			b.WriteRune(r)
			esc = false
		case r == '\\' && q != '\'':
			esc = true
			in = true
		case q != 0:
			if r == q {
				q = 0
			} else {
				b.WriteRune(r)
			}
		case r == '"' || r == '\'':
			q = r
			in = true
		case r == ' ' || r == '\t' || r == '\n':
			if in {
				out = append(out, b.String())
				b.Reset()
				in = false
			}
		default:
			b.WriteRune(r)
			in = true
		}
	}
	if in {
		out = append(out, b.String())
	}
	return out
}

// execForm turns ["a","b"] into "a b"; other text is returned unchanged.
func execForm(s string) string {
	if !strings.HasPrefix(strings.TrimSpace(s), "[") {
		return s
	}
	var arr []string
	if json.Unmarshal([]byte(s), &arr) != nil {
		return s
	}
	return strings.Join(arr, " ")
}

// splitImage splits an image reference into name and tag; digest reports @sha256.
func splitImage(ref string) (name, tag string, digest bool) {
	if i := strings.Index(ref, "@"); i >= 0 {
		return ref[:i], "", true
	}
	slash := strings.LastIndex(ref, "/")
	if c := strings.LastIndex(ref, ":"); c > slash {
		return ref[:c], ref[c+1:], false
	}
	return ref, "", false
}

func isNodeImage(ref string) bool {
	name, _, _ := splitImage(strings.ToLower(ref))
	return name[strings.LastIndex(name, "/")+1:] == "node"
}

var secretKeyRe = regexp.MustCompile(`(?i)(PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|APIKEY|PRIVATE_KEY|ACCESS_KEY|CREDENTIALS)`)

func literal(v string) bool {
	v = strings.TrimSpace(v)
	return v != "" && !strings.HasPrefix(v, "$") && !strings.Contains(v, "${")
}

// kv parses ENV/ARG arguments into ordered key/value pairs; has reports "=".
type kvPair struct {
	Key, Val string
	Has      bool
}

func kvPairs(cmd, args string) []kvPair {
	ws := words(args)
	if len(ws) == 0 {
		return nil
	}
	if cmd == "ENV" && !strings.Contains(ws[0], "=") {
		// legacy ENV KEY value with spaces
		f := strings.Fields(args)
		val := strings.TrimSpace(strings.TrimPrefix(args, f[0]))
		return []kvPair{{Key: f[0], Val: strings.Join(words(val), " "), Has: true}}
	}
	var out []kvPair
	for _, w := range ws {
		k, v, has := strings.Cut(w, "=")
		out = append(out, kvPair{Key: k, Val: v, Has: has})
	}
	return out
}

var (
	runSplitRe  = regexp.MustCompile(`&&|\|\||;|\||\n|\(|\)`)
	envAssignRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)
	curlPipeRe  = regexp.MustCompile(`(?i)\b(curl|wget)\b[^|;&]*\|\s*(sudo\s+(-\S+\s+)*)?(env\s+)?(/usr)?(/bin/)?(ba|z|da|k)?sh\b`)
	curlSubstRe = regexp.MustCompile(`(?i)\b(ba|z|da|k)?sh\s+(-\w+\s+)*(<\(|["']?\$\()\s*(curl|wget)\b`)
)

// subCommands splits a RUN body into simple commands (tokens), with leading
// env assignments removed. sudo reports whether any command used sudo.
func subCommands(run string) (cmds [][]string, sudo bool) {
	for _, part := range runSplitRe.Split(run, -1) {
		ws := words(part)
		for len(ws) > 0 && (envAssignRe.MatchString(ws[0]) || ws[0] == "exec" || ws[0] == "sudo") {
			if ws[0] == "sudo" {
				sudo = true
				ws = ws[1:]
				for len(ws) > 0 && strings.HasPrefix(ws[0], "-") {
					ws = ws[1:]
				}
				continue
			}
			ws = ws[1:]
		}
		if len(ws) > 0 {
			cmds = append(cmds, ws)
		}
	}
	return cmds, sudo
}

func hasAny(ws []string, flags ...string) bool {
	for _, w := range ws {
		for _, f := range flags {
			if w == f || strings.HasPrefix(w, f+"=") {
				return true
			}
		}
	}
	return false
}

// firstVerb returns the first non-flag token after the tool name.
func firstVerb(ws []string) string {
	for _, w := range ws[1:] {
		if !strings.HasPrefix(w, "-") {
			return w
		}
	}
	return ""
}

// installKind classifies a command: "" (not an install), or the tool name.
// lockfix is the suggested lockfile-strict command when the install is not strict.
func installKind(ws []string) (tool, lockfix string) {
	if len(ws) == 0 {
		return "", ""
	}
	tool = filepath.Base(ws[0])
	verb := firstVerb(ws)
	global := hasAny(ws, "-g", "--global", "--location")
	switch tool {
	case "npm":
		switch verb {
		case "ci", "clean-install", "install-clean", "isntall-clean", "ic":
			return "npm", ""
		case "install", "i", "in", "ins", "inst", "insta", "instal", "isnt", "isnta", "isntal", "isntall", "add":
			if global {
				return "", ""
			}
			return "npm", "RUN npm ci"
		}
	case "yarn":
		if verb == "global" {
			return "", ""
		}
		if verb == "" || verb == "install" {
			if hasAny(ws, "--frozen-lockfile", "--immutable") {
				return "yarn", ""
			}
			return "yarn", "RUN yarn install --immutable"
		}
	case "pnpm":
		if verb == "install" || verb == "i" {
			if global {
				return "", ""
			}
			if hasAny(ws, "--frozen-lockfile") {
				return "pnpm", ""
			}
			return "pnpm", "RUN pnpm install --frozen-lockfile"
		}
	case "bun":
		if (verb == "install" || verb == "i") && !global {
			return "bun", ""
		}
	}
	return "", ""
}

var archiveRe = regexp.MustCompile(`(?i)\.(tar|tar\.gz|tgz|tar\.xz|txz|tar\.bz2|tbz2?|tar\.zst)$`)

// copySources returns the source paths and flags of a COPY/ADD instruction.
func copySources(args string) (srcs []string, flags []string) {
	var ws []string
	if strings.HasPrefix(strings.TrimSpace(args), "[") {
		var arr []string
		if json.Unmarshal([]byte(args), &arr) == nil {
			ws = arr
		}
	}
	if ws == nil {
		ws = words(args)
	}
	var rest []string
	for _, w := range ws {
		if strings.HasPrefix(w, "--") && len(rest) == 0 {
			flags = append(flags, w)
			continue
		}
		rest = append(rest, w)
	}
	if len(rest) < 2 || strings.HasPrefix(rest[0], "<<") {
		return nil, flags
	}
	return rest[:len(rest)-1], flags
}

func hasFlag(flags []string, name string) bool {
	for _, f := range flags {
		if f == name || strings.HasPrefix(f, name+"=") {
			return true
		}
	}
	return false
}

// dockerignore reports whether the build context ignores .env and node_modules.
// exists is false when no .dockerignore applies.
func dockerignore(dockerfile string) (exists, env, nodeModules bool) {
	dir := filepath.Dir(dockerfile)
	var data []byte
	var err error
	for _, p := range []string{dockerfile + ".dockerignore", filepath.Join(dir, ".dockerignore")} {
		if data, err = os.ReadFile(p); err == nil {
			break
		}
	}
	if err != nil {
		return false, false, false
	}
	var pats []string
	for _, l := range strings.Split(string(data), "\n") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") {
			pats = append(pats, l)
		}
	}
	ignored := func(name string) bool {
		state := false
		for _, p := range pats {
			neg := strings.HasPrefix(p, "!")
			p = strings.TrimSpace(strings.TrimPrefix(p, "!"))
			p = strings.TrimPrefix(strings.TrimPrefix(p, "./"), "/")
			for strings.HasPrefix(p, "**/") {
				p = p[3:]
			}
			p = strings.TrimSuffix(strings.TrimSuffix(p, "/**"), "/")
			if p == "**" || p == "*" {
				state = !neg
				continue
			}
			if ok, _ := filepath.Match(p, name); ok {
				state = !neg
			}
		}
		return state
	}
	return true, ignored(".env"), ignored("node_modules")
}

type dfCtx struct {
	file       string // relative path for reports
	path       string // absolute path
	src        string
	healthElse bool // some compose file defines a healthcheck
}

func (c *dfCtx) issue(line int, rule, sev string, title, detail i18n.T, fix string) report.DockerIssue {
	return report.DockerIssue{File: c.file, Line: line, Rule: rule, Severity: sev, Title: title, Detail: detail, Fix: fix}
}

func checkDockerfile(c *dfCtx) []report.DockerIssue {
	var out []report.DockerIssue
	ins := parseDockerfile(c.src)
	sts := stages(ins)
	if len(sts) == 0 {
		return nil
	}
	aptDone, ignoreDone := false, false
	for _, st := range sts {
		out = append(out, c.fromRule(st)...)
		for _, in := range st.Body {
			switch in.Cmd {
			case "ENV", "ARG":
				out = append(out, c.secretRule(in)...)
			case "RUN":
				var apt bool
				out = append(out, c.runRules(in, &apt, aptDone)...)
				aptDone = aptDone || apt
			case "ADD", "COPY":
				srcs, flags := copySources(in.Args)
				if !ignoreDone && !hasFlag(flags, "--from") {
					for _, s := range srcs {
						if s == "." || s == "./" {
							if is, ok := c.ignoreRule(in); ok {
								out = append(out, is)
							}
							ignoreDone = true
							break
						}
					}
				}
				if in.Cmd == "ADD" {
					out = append(out, c.addRule(in, srcs, flags)...)
				}
			case "EXPOSE":
				for _, w := range words(in.Args) {
					if w == "22" || strings.EqualFold(w, "22/tcp") {
						out = append(out, c.issue(in.Line, "dockerfile-ssh-port", "medium",
							i18n.F("SSH portu (22) açılır", "SSH port 22 is exposed"),
							i18n.F("Konteynerdə SSH işlətmək hücum səthini artırır; daxil olmaq üçün `docker exec` istifadə et.",
								"Running SSH in a container widens the attack surface; use `docker exec` to get a shell instead."), ""))
						break
					}
				}
			}
		}
	}
	final := sts[len(sts)-1]
	out = append(out, c.userRule(final)...)
	if !c.healthElse && final.last("HEALTHCHECK") == nil && !strings.EqualFold(final.rootImage(), "scratch") {
		fix := `HEALTHCHECK CMD curl -fs http://localhost:3000/health || exit 1`
		if isNodeImage(final.rootImage()) {
			fix = `HEALTHCHECK CMD node -e "fetch('http://localhost:3000/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"`
		}
		out = append(out, c.issue(final.Line, "dockerfile-no-healthcheck", "low",
			i18n.F("HEALTHCHECK yoxdur", "No HEALTHCHECK"),
			i18n.F("Sağlamlıq yoxlaması olmadan Docker donmuş tətbiqi işlək sayır və yenidən başlatmır.",
				"Without a health check Docker treats a hung app as healthy and never restarts it."), fix))
	}
	return out
}

func (c *dfCtx) fromRule(st *stage) []report.DockerIssue {
	img := st.Image
	if img == "" || strings.EqualFold(img, "scratch") || st.Base != nil || strings.Contains(img, "$") {
		return nil
	}
	name, tag, digest := splitImage(img)
	if digest || (tag != "" && !strings.EqualFold(tag, "latest")) {
		return nil
	}
	fix := "FROM " + name + ":<version>"
	if isNodeImage(img) {
		fix = "FROM node:22-bookworm-slim"
	}
	if st.Name != "" {
		fix += " AS " + st.Name
	}
	return []report.DockerIssue{c.issue(st.Line, "dockerfile-latest-tag", "medium",
		i18n.F("`%s` image-i sabit versiyasız istifadə olunur", "Image `%s` is not pinned to a version", img),
		i18n.F("`latest` və ya teqsiz image hər build-də dəyişə bilər; build-lər təkrarlanmır və gözlənilmədən sınır.",
			"An untagged or `latest` image changes between builds, so builds are not reproducible and can break unexpectedly."), fix)}
}

func (c *dfCtx) userRule(final *stage) []report.DockerIssue {
	root := strings.ToLower(final.rootImage())
	name, tag, _ := splitImage(root)
	if root == "scratch" || (strings.Contains(name, "distroless") && strings.Contains(tag, "nonroot")) ||
		strings.HasPrefix(name, "cgr.dev/chainguard/") {
		return nil
	}
	u := final.last("USER")
	line := final.Line
	if u != nil {
		user := strings.ToLower(strings.TrimSpace(u.Args))
		if user != "root" && user != "0" && user != "0:0" && user != "root:root" {
			return nil
		}
		line = u.Line
	}
	fix := "USER 10001"
	if isNodeImage(root) {
		fix = "USER node"
	}
	return []report.DockerIssue{c.issue(line, "dockerfile-root-user", "high",
		i18n.F("Konteyner root istifadəçisi ilə işləyir", "Container runs as root"),
		i18n.F("Son mərhələdə root olmayan USER yoxdur; tətbiqdəki boşluq hücumçuya konteynerdə tam səlahiyyət verir.",
			"The final stage has no non-root USER, so a bug in the app gives an attacker full control of the container."), fix)}
}

func (c *dfCtx) secretRule(in instr) []report.DockerIssue {
	var out []report.DockerIssue
	for _, p := range kvPairs(in.Cmd, in.Args) {
		if !secretKeyRe.MatchString(p.Key) {
			continue
		}
		mount := "RUN --mount=type=secret,id=" + strings.ToLower(p.Key) + ",env=" + p.Key + " <command>"
		switch {
		case p.Has && literal(p.Val):
			out = append(out, c.issue(in.Line, "dockerfile-secret-env", "high",
				i18n.F("`%s` sirri Dockerfile-da açıq yazılıb", "Secret `%s` is hard-coded in the Dockerfile", p.Key),
				i18n.F("%s dəyəri image-ə və onun tarixçəsinə düşür; image-i götürən hər kəs onu oxuya bilər.",
					"The %s value is baked into the image and its history, readable by anyone who pulls it.", in.Cmd), mount))
		case in.Cmd == "ARG" && !p.Has:
			out = append(out, c.issue(in.Line, "dockerfile-secret-arg", "medium",
				i18n.F("`%s` sirri build arqumenti kimi ötürülür", "Secret `%s` is passed as a build argument", p.Key),
				i18n.F("Build arqumentləri image tarixçəsində qalır; əvəzinə BuildKit secret mount istifadə et.",
					"Build args stay in the image history; use a BuildKit secret mount instead."), mount))
		}
	}
	return out
}

func (c *dfCtx) runRules(in instr, apt *bool, aptDone bool) []report.DockerIssue {
	var out []report.DockerIssue
	body := execForm(in.Args)
	// drop RUN flags such as --mount=... --network=...
	for strings.HasPrefix(body, "--") {
		i := strings.IndexAny(body, " \t")
		if i < 0 {
			body = ""
			break
		}
		body = strings.TrimSpace(body[i:])
	}
	if curlPipeRe.MatchString(body) || curlSubstRe.MatchString(body) {
		out = append(out, c.issue(in.Line, "dockerfile-curl-pipe", "high",
			i18n.F("İnternetdən skript birbaşa shell-ə ötürülür", "Remote script is piped straight into a shell"),
			i18n.F("`curl | sh` yoxlanmamış kodu icra edir; faylı yüklə, checksum-u yoxla, sonra işlət.",
				"`curl | sh` runs unverified code; download the file, verify its checksum, then run it."),
			"RUN curl -fsSLo /tmp/install.sh <url> && echo \"<sha256>  /tmp/install.sh\" | sha256sum -c - && sh /tmp/install.sh"))
	}
	cmds, sudo := subCommands(body)
	lockDone, scriptsDone := false, false
	for _, ws := range cmds {
		tool, lockfix := installKind(ws)
		if tool != "" && lockfix != "" && !lockDone {
			lockDone = true
			out = append(out, c.issue(in.Line, "dockerfile-npm-install", "medium",
				i18n.F("Lock faylına sadiq olmayan quraşdırma (`%s`)", "Install does not enforce the lockfile (`%s`)", strings.Join(ws, " ")),
				i18n.F("Bu əmr lock faylından fərqli versiyalar quraşdıra bilər; build-lər təkrarlanmır və təhlükəli yeni versiya gələ bilər.",
					"This command can install versions other than the lockfile pins, so builds drift and a malicious new release can slip in."), lockfix))
		}
		if tool != "" && !scriptsDone && !hasAny(ws, "--ignore-scripts") {
			scriptsDone = true
			out = append(out, c.issue(in.Line, "dockerfile-install-scripts", "low",
				i18n.F("Paket quraşdırma skriptləri işə düşür", "Package install scripts are allowed to run"),
				i18n.F("Təchizat zənciri hücumları adətən install skriptlərində olur; layihəyə native build skriptləri lazım deyilsə, `--ignore-scripts` əlavə et.",
					"Supply-chain attacks usually live in install scripts; add `--ignore-scripts` if the project needs no native build scripts."),
				"RUN "+strings.Join(ws, " ")+" --ignore-scripts"))
		}
		if !aptDone && !*apt && len(ws) >= 2 && (ws[0] == "apt-get" || ws[0] == "apt") && firstVerb(ws) == "install" &&
			!hasAny(ws, "--no-install-recommends") {
			*apt = true
			fixed := []string{}
			for _, w := range ws {
				fixed = append(fixed, w)
				if w == "install" {
					fixed = append(fixed, "--no-install-recommends")
				}
			}
			out = append(out, c.issue(in.Line, "dockerfile-apt-recommends", "low",
				i18n.F("`apt-get install` tövsiyə olunan paketləri də quraşdırır", "`apt-get install` also pulls recommended packages"),
				i18n.F("Lazımsız paketlər image-i böyüdür və zəiflik sayını artırır.",
					"Unneeded packages bloat the image and add vulnerabilities."), "RUN "+strings.Join(fixed, " ")))
		}
	}
	if sudo {
		out = append(out, c.issue(in.Line, "dockerfile-sudo", "low",
			i18n.F("RUN daxilində sudo istifadə olunur", "RUN uses sudo"),
			i18n.F("Build zamanı sudo lazım deyil; root lazım olan addımları USER-dən əvvəl icra et və image-də sudo saxlama.",
				"sudo is not needed at build time; run root steps before switching USER and keep sudo out of the image."), ""))
	}
	return out
}

func (c *dfCtx) addRule(in instr, srcs, flags []string) []report.DockerIssue {
	var out []report.DockerIssue
	url, local := false, false
	for _, s := range srcs {
		ls := strings.ToLower(s)
		switch {
		case strings.HasPrefix(ls, "http://") || strings.HasPrefix(ls, "https://"):
			url = true
		case strings.HasPrefix(ls, "git@") || strings.HasSuffix(ls, ".git"):
		case !archiveRe.MatchString(s):
			local = true
		}
	}
	if url && !hasFlag(flags, "--checksum") {
		out = append(out, c.issue(in.Line, "dockerfile-add-url", "medium",
			i18n.F("ADD faylı URL-dən yoxlamasız yükləyir", "ADD downloads a file from a URL without verification"),
			i18n.F("Uzaq fayl dəyişdirilə bilər; `--checksum` ilə hash-i sabitlə.",
				"The remote file can change under you; pin its hash with `--checksum`."),
			"ADD --checksum=sha256:<hash> "+strings.Join(words(in.Args), " ")))
	}
	if local {
		args := in.Args
		out = append(out, c.issue(in.Line, "dockerfile-add-local", "low",
			i18n.F("Lokal fayllar üçün ADD əvəzinə COPY istifadə et", "Use COPY instead of ADD for local files"),
			i18n.F("ADD arxivləri avtomatik açır və URL-ləri yükləyir; COPY daha proqnozlaşdırılandır.",
				"ADD auto-extracts archives and fetches URLs; COPY is predictable."), "COPY "+args))
	}
	return out
}

func (c *dfCtx) ignoreRule(in instr) (report.DockerIssue, bool) {
	exists, env, nm := dockerignore(c.path)
	if exists && env {
		return report.DockerIssue{}, false
	}
	var d i18n.T
	switch {
	case !exists:
		d = i18n.F("`.dockerignore` faylı yoxdur, ona görə `.env` sirləri və node_modules image-ə kopyalanır.",
			"There is no `.dockerignore`, so `.env` secrets and node_modules are copied into the image.")
	case !nm:
		d = i18n.F("`.dockerignore` faylında `.env` və node_modules yoxdur, ona görə sirlər və lokal paketlər image-ə düşür.",
			"`.dockerignore` does not list `.env` or node_modules, so secrets and local packages end up in the image.")
	default:
		d = i18n.F("`.dockerignore` faylında `.env` yoxdur, ona görə sirlər image-ə düşə bilər.",
			"`.dockerignore` does not list `.env`, so secrets can end up in the image.")
	}
	return c.issue(in.Line, "dockerfile-dockerignore", "medium",
		i18n.F("Bütün qovluq kopyalanır, `.env` qorunmur", "Whole context is copied without excluding `.env`"), d, ".env*"), true
}
