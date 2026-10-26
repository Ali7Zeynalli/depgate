// DepGate scans Node.js projects for vulnerable, malicious and outdated npm
// packages and answers two questions per package: do I need to update, and
// does the update affect my code. It runs locally and changes nothing.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Ali7Zeynalli/depgate/internal/app"
	"github.com/Ali7Zeynalli/depgate/internal/auth"
	"github.com/Ali7Zeynalli/depgate/internal/i18n"
	"github.com/Ali7Zeynalli/depgate/internal/mcp"
	"github.com/Ali7Zeynalli/depgate/internal/project"
	"github.com/Ali7Zeynalli/depgate/internal/report"
	"github.com/Ali7Zeynalli/depgate/internal/scan"
	"github.com/Ali7Zeynalli/depgate/internal/sources"
	"github.com/Ali7Zeynalli/depgate/internal/store"
	"github.com/Ali7Zeynalli/depgate/internal/web"
)

var version = "0.1.0-dev" // set by goreleaser: -ldflags "-X main.version=..."

type config struct {
	port      int
	addr      string
	noOpen    bool
	offline   bool
	depth     int
	jsonOut   bool
	ci        bool
	failOn    string
	cooldown  int
	rescan    int
	push      string
	token     string
	version   bool
	health    bool
	resetPw   bool
	printTok  bool
	chownData string
	noAuth    bool
	view      string
	data      string
	roots     multi
	allowHost multi
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

var lang = i18n.Lang()

// L picks the CLI message in the current language.
func L(az, en string) string {
	if lang == "az" {
		return az
	}
	return en
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "mcp" {
		return runMCP(args[1:], os.Stdin, stdout, stderr)
	}
	var c config
	container := os.Getenv("DEPGATE_CONTAINER") == "1"
	fs := flag.NewFlagSet("depgate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.IntVar(&c.port, "port", 7777, "veb interfeysin portu")
	defAddr := "127.0.0.1"
	if container {
		defAddr = "0.0.0.0"
	}
	fs.StringVar(&c.addr, "addr", envOr("DEPGATE_ADDR", defAddr), "listen address (0.0.0.0 in a container)")
	fs.BoolVar(&c.noOpen, "no-open", container, "do not open the browser")
	fs.BoolVar(&c.offline, "offline", false, "never use the network, cache only")
	fs.IntVar(&c.depth, "depth", 3, "project discovery depth")
	fs.BoolVar(&c.jsonOut, "json", false, "scan once and print the JSON report to stdout")
	fs.BoolVar(&c.ci, "ci", false, "CI mode: scan once, print a summary, set the exit code")
	fs.StringVar(&c.failOn, "fail-on", "high", "CI: fail at this severity or above (critical|high|moderate|low)")
	fs.IntVar(&c.cooldown, "cooldown", 3, "never pick versions younger than N days as targets")
	fs.IntVar(&c.rescan, "rescan", envInt("DEPGATE_RESCAN_HOURS", 12), "scan projects again when their last scan is older than N hours (0 = off; the UI can change it)")
	fs.StringVar(&c.push, "push", "", "scan once and POST the report to this URL")
	fs.StringVar(&c.token, "token", os.Getenv("DEPGATE_PUSH_TOKEN"), "bearer token for --push (or DEPGATE_PUSH_TOKEN)")
	fs.BoolVar(&c.version, "version", false, "print the version")
	fs.BoolVar(&c.health, "health", false, "check a running server (Docker HEALTHCHECK); exit 0 = healthy")
	fs.BoolVar(&c.printTok, "print-token", false, "print the API/MCP token (for agents connecting to /mcp) and exit")
	fs.BoolVar(&c.resetPw, "reset-password", false, "forget the UI password; the next visit asks for a new one")
	fs.StringVar(&c.chownData, "chown-data", "", "UID:GID — give the data folder to this user and exit (Docker init step, needs root)")
	fs.BoolVar(&c.noAuth, "no-auth", false, "disable the UI password (only allowed on 127.0.0.1; not recommended)")
	fs.StringVar(&c.view, "view", "", "open a saved JSON report in the UI (read-only)")
	fs.StringVar(&c.data, "data", os.Getenv("DEPGATE_DATA"), "folder for the project list and reports (default ~/.config/depgate; DEPGATE_DATA)")
	fs.Var(&c.roots, "root", "folder the UI may browse (repeatable; default: home; DEPGATE_ROOTS)")
	fs.Var(&c.allowHost, "allow-host", "extra allowed Host name, e.g. depgate.lan (repeatable)")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "DepGate %s — npm dependency security and update advisor for Node.js projects\n\n", version)
		fmt.Fprintln(stderr, "Usage:\n  depgate [flags] [folder]\n\nExamples:\n  depgate                 open the UI; if this folder is a project, add and scan it\n  depgate ~/projects      add every project below ~/projects\n  depgate --json > r.json scan once, print JSON\n  depgate --ci --fail-on high\n  depgate --view r.json   open a saved report\n\nSet DEPGATE_LANG=az for Azerbaijani messages.\n\nFlags:")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if c.version {
		fmt.Fprintln(stdout, "depgate", version)
		return 0
	}
	if c.health {
		resp, err := (&http.Client{Timeout: 3 * time.Second}).Get(fmt.Sprintf("http://127.0.0.1:%d/healthz", c.port))
		if err != nil || resp.StatusCode != http.StatusOK {
			return 1
		}
		resp.Body.Close()
		return 0
	}
	if fs.NArg() > 1 {
		fmt.Fprintln(stderr, L("depgate: yalnız bir qovluq ver", "depgate: give a single folder"))
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	dataDir, cacheDir := dirsFor(c.data)

	// started as root in the container: become the owner of the mounted folders, never stay root
	if container && c.chownData == "" {
		if err := dropRoot(dataDir, true); err != nil {
			fmt.Fprintln(stderr, "depgate:", err)
			return 1
		}
	}

	if c.chownData != "" {
		if err := chownTree(dataDir, c.chownData); err != nil {
			fmt.Fprintln(stderr, "depgate:", err)
			return 1
		}
		return 0
	}
	if c.printTok {
		st, err := store.Open(dataDir)
		if err == nil {
			var tok string
			if tok, err = st.Token(); err == nil {
				fmt.Fprintln(stdout, tok)
				return 0
			}
		}
		fmt.Fprintln(stderr, "depgate:", err)
		return 1
	}
	if c.resetPw {
		if err := auth.Reset(dataDir); err != nil {
			fmt.Fprintln(stderr, "depgate:", err)
			return 1
		}
		fmt.Fprintln(stderr, L("Parol silindi. DepGate-i açanda yeni parol təyin etməyin istəniləcək.", "Password removed. Next time you open DepGate you will be asked to set a new one."))
		return 0
	}

	if c.view != "" {
		b, err := os.ReadFile(c.view)
		if err != nil {
			fmt.Fprintln(stderr, "depgate:", err)
			return 2
		}
		var rep report.Report
		if err := json.Unmarshal(b, &rep); err != nil || rep.Schema != report.Schema {
			fmt.Fprintln(stderr, L("depgate: depgate/report@1 hesabatı deyil:", "depgate: not a depgate/report@1 report:"), c.view)
			return 2
		}
		return serve(ctx, c, app.ReadOnly(&rep), web.NewToken(), nil, stderr, nil)
	}

	opt := scan.Options{Version: version, CooldownDays: c.cooldown, Offline: c.offline}
	fetcher := func() sources.Fetcher { return sources.NewHTTP(cacheDir, c.offline, version) }

	// one-shot modes: scan, print, exit
	if c.jsonOut || c.ci || c.push != "" {
		root := "."
		if fs.NArg() > 0 {
			root = fs.Arg(0)
		}
		dirs, err := project.Find(root, c.depth)
		if err != nil {
			fmt.Fprintln(stderr, "depgate:", err)
			return 2
		}
		if len(dirs) == 0 {
			fmt.Fprintf(stderr, L("depgate: %s altında asılılığı olan package.json tapılmadı\n", "depgate: no package.json with dependencies under %s\n"), root)
			return 2
		}
		if !c.jsonOut {
			opt.Progress = func(s string) { fmt.Fprintln(stderr, s) }
		}
		if c.push != "" {
			flushOutbox(ctx, cacheDir, c.push, c.token, stderr)
		}
		rep := scan.Run(ctx, fetcher(), dirs, opt)
		if ctx.Err() != nil {
			return 130
		}
		if c.push != "" {
			if err := push(ctx, c.push, c.token, rep); err != nil {
				fmt.Fprintln(stderr, L("depgate: göndərilmədi, növbəti dəfə təkrar ediləcək:", "depgate: push failed, will retry next run:"), err)
				saveOutbox(cacheDir, rep)
			} else if !c.jsonOut {
				fmt.Fprintln(stderr, L("Hesabat göndərildi:", "Report sent:"), c.push)
			}
		}
		if c.jsonOut {
			enc := json.NewEncoder(stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(rep); err != nil {
				return 1
			}
		} else {
			printSummary(stderr, rep)
		}
		return exitCode(rep, c)
	}

	// UI mode: remembered projects + background scans
	st, err := store.Open(dataDir)
	if err != nil {
		fmt.Fprintln(stderr, L("depgate: yaddaş açılmadı:", "depgate: cannot open data folder:"), err)
		if errors.Is(err, os.ErrPermission) {
			fmt.Fprintf(stderr, L("  %s qovluğuna bu istifadəçi (uid %d) yaza bilmir.\n", "  this user (uid %d) cannot write to %s.\n"), permArgs(dataDir)...)
			if container {
				fmt.Fprintln(stderr, L("  Docker volume-u köhnə versiya yaradıb. Düzəliş: docker compose down -v && docker compose up -d --build", "  The Docker volume was created by an older version. Fix: docker compose down -v && docker compose up -d --build"))
			} else {
				fmt.Fprintln(stderr, L("  Başqa qovluq ver: --data <qovluq> və ya DEPGATE_DATA", "  Use another folder: --data <dir> or DEPGATE_DATA"))
			}
		}
		return 1
	}
	if c.noAuth && !loopback(c.addr) {
		fmt.Fprintln(stderr, L("depgate: --no-auth yalnız 127.0.0.1 ünvanında icazəlidir", "depgate: --no-auth is only allowed on 127.0.0.1"))
		return 2
	}
	var au *auth.Auth
	if !c.noAuth {
		if au, err = auth.Open(dataDir, os.Getenv("DEPGATE_PASSWORD")); err != nil {
			fmt.Fprintln(stderr, "depgate:", err)
			return 1
		}
	}
	token, err := st.Token()
	if err != nil {
		fmt.Fprintln(stderr, "depgate:", err)
		return 1
	}
	roots := rootsFor(c.roots)
	var initial string
	if fs.NArg() > 0 {
		initial = fs.Arg(0)
	} else if _, err := os.Stat("package.json"); err == nil && !container {
		initial = "."
	}
	if initial != "" {
		if abs, err := filepath.Abs(initial); err == nil && !within(abs, roots) {
			roots = append(roots, abs)
		}
	}
	m := &app.Manager{Store: st, Fetcher: fetcher, Opt: opt, Roots: roots, Depth: c.depth, Container: container, Rescan: c.rescan}
	m.Start(ctx)
	if initial != "" {
		dirs, err := m.Add(initial)
		if err != nil {
			fmt.Fprintln(stderr, "depgate:", err)
		} else {
			_ = m.ScanBy(dirs, "cli") // re-scan even when already remembered
			fmt.Fprintf(stderr, L("%d layihə skan olunur (arxa planda)…\n", "scanning %d project(s) in the background…\n"), len(dirs))
		}
	}
	fmt.Fprintf(stderr, L("Yadda saxlanan layihələr: %d · Kök qovluqlar: %s\n", "Remembered projects: %d · Browsable roots: %s\n"), len(st.Projects()), strings.Join(roots, ", "))
	mcpSrv := &mcp.Server{Store: st, Fetcher: fetcher, Opt: opt, Version: version, Roots: roots, Log: stderr}
	return serve(ctx, c, m, token, au, stderr, mcpSrv.HTTPHandler())
}

// permArgs orders the arguments of the permission message for the current language.
func permArgs(dir string) []any {
	if lang == "az" {
		return []any{dir, os.Getuid()}
	}
	return []any{os.Getuid(), dir}
}

// chownTree gives dir and everything inside it to uid:gid (used by the Docker init step).
func chownTree(dir, ids string) error {
	u, g, ok := strings.Cut(ids, ":")
	uid, err1 := strconv.Atoi(u)
	gid, err2 := strconv.Atoi(g)
	if !ok || err1 != nil || err2 != nil || uid < 0 || gid < 0 {
		return fmt.Errorf("--chown-data wants UID:GID, got %q", ids)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil // never follow links out of the volume
		}
		return os.Lchown(p, uid, gid)
	})
}

func loopback(addr string) bool {
	return addr == "" || addr == "127.0.0.1" || addr == "localhost" || addr == "::1"
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func dirsFor(data string) (dataDir, cacheDir string) {
	if data != "" {
		return data, filepath.Join(data, "cache")
	}
	if d, err := os.UserConfigDir(); err == nil {
		dataDir = filepath.Join(d, "depgate")
	} else {
		dataDir = ".depgate"
	}
	if d, err := os.UserCacheDir(); err == nil {
		cacheDir = filepath.Join(d, "depgate")
	}
	return dataDir, cacheDir
}

func rootsFor(flagRoots []string) []string {
	var rs []string
	rs = append(rs, flagRoots...)
	if env := os.Getenv("DEPGATE_ROOTS"); env != "" {
		rs = append(rs, filepath.SplitList(env)...)
	}
	if len(rs) == 0 {
		if h, err := os.UserHomeDir(); err == nil {
			rs = append(rs, h)
		} else {
			rs = append(rs, string(filepath.Separator))
		}
	}
	var out []string
	seen := map[string]bool{}
	for _, r := range rs {
		if a, err := filepath.Abs(r); err == nil && !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	return out
}

func within(p string, roots []string) bool {
	for _, r := range roots {
		if p == r || strings.HasPrefix(p, r+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func serve(ctx context.Context, c config, b web.Backend, token string, au *auth.Auth, stderr io.Writer, mcpH http.Handler) int {
	ln, port, err := web.Listen(c.addr, c.port)
	if err != nil {
		fmt.Fprintln(stderr, L("depgate: port açılmadı:", "depgate: cannot open port:"), err)
		return 1
	}
	readOnly := au == nil && !c.noAuth // --view: one-time link, no password
	srv := &web.Server{Token: token, B: b, Auth: au, NoAuth: c.noAuth || readOnly, AllowHosts: c.allowHost, MCP: mcpH}
	url := fmt.Sprintf("http://127.0.0.1:%d/", port)
	fmt.Fprintf(stderr, "\nDepGate: %s\n", url)
	switch {
	case c.noAuth:
		fmt.Fprintln(stderr, L("XƏBƏRDARLIQ: parol söndürülüb (--no-auth).", "WARNING: password disabled (--no-auth)."))
	case readOnly:
	case !au.Configured():
		fmt.Fprintln(stderr, L("İlk açılış: brauzerdə parol təyin et.", "First visit: set a password in the browser."))
	case au.FromEnv():
		fmt.Fprintln(stderr, L("Parol DEPGATE_PASSWORD-dan götürülür.", "Password comes from DEPGATE_PASSWORD."))
	default:
		fmt.Fprintln(stderr, L("Parolu unutmusan? depgate --reset-password", "Forgot the password? depgate --reset-password"))
	}
	fmt.Fprintln(stderr, L("Dayandırmaq üçün Ctrl+C", "Press Ctrl+C to stop"))
	if !c.noOpen {
		openBrowser(url)
	}
	hs := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = hs.Shutdown(sctx)
	}()
	if err := hs.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(stderr, "depgate:", err)
		return 1
	}
	return 0
}

var sevRank = map[string]int{"low": 1, "moderate": 2, "high": 3, "critical": 4}

func exitCode(rep *report.Report, c config) int {
	if !c.ci {
		return 0
	}
	lim := sevRank[strings.ToLower(c.failOn)]
	if lim == 0 {
		lim = 3
	}
	for _, p := range rep.Projects {
		for _, f := range p.Findings {
			if f.Kind == "malware" || (f.Kind == "vuln" && sevRank[f.Severity] >= lim && !f.Dev) {
				return 1
			}
		}
	}
	return 0
}

func printSummary(w io.Writer, rep *report.Report) {
	fmt.Fprintln(w)
	for _, p := range rep.Projects {
		s := p.Summary
		node := ""
		if p.Node != nil && p.Node.Version != "" {
			node = " · Node " + p.Node.Version
		}
		fmt.Fprintf(w, "%s (%d paket%s)\n", p.Name, p.Packages, node)
		if s.Malware > 0 {
			fmt.Fprintf(w, L("  !!! ZƏRƏRLİ PAKET: %d — dərhal hesabata bax\n", "  !!! MALICIOUS PACKAGE: %d — open the report now\n"), s.Malware)
		}
		fmt.Fprintf(w, L("  İndi et: kod dəyişmir %d · kod dəyişir %d · Planla %d · İstəyə görə %d · Lazım deyil %d\n", "  Do now: no code change %d · code change %d · Plan %d · Optional %d · Nothing to do %d\n"), s.NowEasy, s.NowCode, s.Plan, s.Optional, s.OK)
		var urgent []report.Finding
		for _, f := range p.Findings {
			if f.Group == report.GroupNowEasy || f.Group == report.GroupNowCode {
				urgent = append(urgent, f)
			}
		}
		sort.SliceStable(urgent, func(i, j int) bool { return urgent[i].Priority > urgent[j].Priority })
		for i, f := range urgent {
			if i == 8 {
				fmt.Fprintf(w, "  … daha %d\n", len(urgent)-8)
				break
			}
			arrow := ""
			if f.Target != "" {
				arrow = " → " + f.Target
			}
			fmt.Fprintf(w, "  - %s %s%s [%s, P%d]\n", f.Pkg, f.Current, arrow, orKind(f), f.Priority)
		}
		if p.Node != nil && p.Node.Need == report.NeedNow {
			fmt.Fprintf(w, "  - Node: %s\n", i18n.Join(p.Node.Why, lang, "; "))
		}
		if len(p.Errors) > 0 {
			fmt.Fprintf(w, L("  (%d xəbərdarlıq — interfeysdə bax)\n", "  (%d warnings — see the UI)\n"), len(p.Errors))
		}
	}
	for _, e := range rep.Errors {
		fmt.Fprintln(w, L("xəbərdarlıq:", "warning:"), e)
	}
}

func orKind(f report.Finding) string {
	if f.Severity != "" {
		return f.Severity
	}
	return f.Kind
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	cmd.Stdout, cmd.Stderr = nil, nil
	_ = cmd.Start()
}

func push(ctx context.Context, url, token string, rep *report.Report) error {
	b, err := json.Marshal(rep)
	if err != nil {
		return err
	}
	return postJSON(ctx, url, token, b)
}

func postJSON(ctx context.Context, url, token string, b []byte) error {
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

func saveOutbox(cacheDir string, rep *report.Report) {
	if cacheDir == "" {
		return
	}
	dir := filepath.Join(cacheDir, "outbox")
	if os.MkdirAll(dir, 0o700) != nil {
		return
	}
	b, _ := json.Marshal(rep)
	_ = os.WriteFile(filepath.Join(dir, time.Now().UTC().Format("20060102T150405Z")+".json"), b, 0o600)
}

func flushOutbox(ctx context.Context, cacheDir, url, token string, w io.Writer) {
	if cacheDir == "" {
		return
	}
	dir := filepath.Join(cacheDir, "outbox")
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range ents {
		p := filepath.Join(dir, e.Name())
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if postJSON(ctx, url, token, b) == nil {
			_ = os.Remove(p)
			fmt.Fprintln(w, L("Köhnə hesabat göndərildi:", "Queued report sent:"), e.Name())
		}
	}
}

// runMCP serves the Model Context Protocol on stdin/stdout for AI agents.
// stdout carries protocol messages only; diagnostics go to stderr.
func runMCP(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("depgate mcp", flag.ContinueOnError)
	fs.SetOutput(stderr)
	projectDir := fs.String("project", os.Getenv("DEPGATE_PROJECT"), "default project for every tool (default: the working directory; DEPGATE_PROJECT)")
	data := fs.String("data", os.Getenv("DEPGATE_DATA"), "DepGate data folder (shared with the UI)")
	offline := fs.Bool("offline", false, "never use the network, cache only")
	cooldown := fs.Int("cooldown", 3, "never suggest versions younger than N days")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: depgate mcp [--project DIR]\n\nModel Context Protocol server (stdio) for AI coding agents, e.g.\n  claude mcp add depgate -- depgate mcp\n\nFlags:")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	dataDir, cacheDir := dirsFor(*data)
	if os.Getenv("DEPGATE_CONTAINER") == "1" { // `docker exec … depgate mcp` runs as root: write reports as the owner
		if err := dropRoot(dataDir, false); err != nil {
			fmt.Fprintln(stderr, "depgate:", err)
			return 1
		}
	}
	st, err := store.Open(dataDir)
	if err != nil {
		fmt.Fprintln(stderr, "depgate mcp:", err)
		return 1
	}
	hint := ""
	if len(st.Projects()) == 0 {
		cl := &http.Client{Timeout: 700 * time.Millisecond}
		if resp, err := cl.Get("http://127.0.0.1:7777/healthz"); err == nil {
			resp.Body.Close()
			hint = "A DepGate server is running at http://127.0.0.1:7777 with its own data (for example in Docker). To see its projects, connect the agent over HTTP instead: open a project in the DepGate UI, section \"AI & MCP\", button \"Connection command\"."
			fmt.Fprintln(stderr, "depgate mcp:", hint)
		}
	}
	s := &mcp.Server{
		Hint:    hint,
		Store:   st,
		Fetcher: func() sources.Fetcher { return sources.NewHTTP(cacheDir, *offline, version) },
		Opt:     scan.Options{Version: version, CooldownDays: *cooldown, Offline: *offline},
		Project: *projectDir,
		Version: version,
		Log:     stderr,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := s.Serve(ctx, stdin, stdout); err != nil && ctx.Err() == nil {
		fmt.Fprintln(stderr, "depgate mcp:", err)
		return 1
	}
	return 0
}

func envInt(k string, def int) int {
	if v, err := strconv.Atoi(strings.TrimSpace(os.Getenv(k))); err == nil && v >= 0 {
		return v
	}
	return def
}
