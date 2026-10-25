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
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/Ali7Zeynalli/depgate/internal/app"
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
	push      string
	token     string
	version   bool
	health    bool
	view      string
	data      string
	roots     multi
	allowHost multi
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	var c config
	container := os.Getenv("DEPGATE_CONTAINER") == "1"
	fs := flag.NewFlagSet("depgate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.IntVar(&c.port, "port", 7777, "veb interfeysin portu")
	defAddr := "127.0.0.1"
	if container {
		defAddr = "0.0.0.0"
	}
	fs.StringVar(&c.addr, "addr", envOr("DEPGATE_ADDR", defAddr), "dinləniləcək ünvan (konteynerdə 0.0.0.0)")
	fs.BoolVar(&c.noOpen, "no-open", container, "brauzeri avtomatik açma")
	fs.BoolVar(&c.offline, "offline", false, "şəbəkəyə çıxma, yalnız keşdən istifadə et")
	fs.IntVar(&c.depth, "depth", 3, "layihə axtarışının dərinliyi")
	fs.BoolVar(&c.jsonOut, "json", false, "skan et, hesabatı JSON kimi stdout-a yaz, interfeys açma")
	fs.BoolVar(&c.ci, "ci", false, "CI rejimi: skan et, mətn xülasəsi və çıxış kodu")
	fs.StringVar(&c.failOn, "fail-on", "high", "CI-da bu səviyyədən (critical|high|moderate|low) uğursuz ol")
	fs.IntVar(&c.cooldown, "cooldown", 3, "bundan cavan versiyaları (gün) hədəf seçmə")
	fs.StringVar(&c.push, "push", "", "skan et və hesabatı bu URL-ə POST et (interfeys açmır)")
	fs.StringVar(&c.token, "token", os.Getenv("DEPGATE_PUSH_TOKEN"), "--push üçün Bearer token (və ya DEPGATE_PUSH_TOKEN)")
	fs.BoolVar(&c.version, "version", false, "versiyanı göstər")
	fs.BoolVar(&c.health, "health", false, "işləyən serveri yoxla (Docker HEALTHCHECK üçün), 0 = sağlam")
	fs.StringVar(&c.view, "view", "", "saxlanmış JSON hesabatı interfeysdə aç (yalnız baxış)")
	fs.StringVar(&c.data, "data", os.Getenv("DEPGATE_DATA"), "layihə siyahısı və hesabatların qovluğu (standart: ~/.config/depgate)")
	fs.Var(&c.roots, "root", "interfeysdə gəzilə bilən qovluq (təkrarlana bilər; standart: ev qovluğu; DEPGATE_ROOTS)")
	fs.Var(&c.allowHost, "allow-host", "əlavə icazəli Host adı, məs. depgate.lan (təkrarlana bilər)")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "DepGate %s — Node.js layihələri üçün paket təhlükəsizliyi və yeniləmələr\n\n", version)
		fmt.Fprintln(stderr, "İstifadə:\n  depgate [bayraqlar] [qovluq]\n\nNümunələr:\n  depgate                 interfeysi aç; bu qovluq layihədirsə, siyahıya əlavə et və skan et\n  depgate ~/projects      oradakı bütün layihələri əlavə et\n  depgate --json > r.json bir dəfə skan et, JSON yaz\n  depgate --ci --fail-on high\n  depgate --view r.json   saxlanmış hesabata bax\n\nBayraqlar:")
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
		fmt.Fprintln(stderr, "depgate: yalnız bir qovluq ver")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	dataDir, cacheDir := dirsFor(c.data)

	if c.view != "" {
		b, err := os.ReadFile(c.view)
		if err != nil {
			fmt.Fprintln(stderr, "depgate:", err)
			return 2
		}
		var rep report.Report
		if err := json.Unmarshal(b, &rep); err != nil || rep.Schema != report.Schema {
			fmt.Fprintln(stderr, "depgate: depgate/report@1 hesabatı deyil:", c.view)
			return 2
		}
		return serve(ctx, c, app.ReadOnly(&rep), web.NewToken(), stderr)
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
			fmt.Fprintf(stderr, "depgate: %s altında asılılığı olan package.json tapılmadı\n", root)
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
				fmt.Fprintln(stderr, "depgate: göndərilmədi, növbəti dəfə təkrar ediləcək:", err)
				saveOutbox(cacheDir, rep)
			} else if !c.jsonOut {
				fmt.Fprintln(stderr, "Hesabat göndərildi:", c.push)
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
		fmt.Fprintln(stderr, "depgate: yaddaş açılmadı:", err)
		return 1
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
	m := &app.Manager{Store: st, Fetcher: fetcher, Opt: opt, Roots: roots, Depth: c.depth, Container: container}
	m.Start(ctx)
	if initial != "" {
		dirs, err := m.Add(initial)
		if err != nil {
			fmt.Fprintln(stderr, "depgate:", err)
		} else {
			_ = m.Scan(dirs) // re-scan even when already remembered
			fmt.Fprintf(stderr, "%d layihə skan olunur (arxa planda)…\n", len(dirs))
		}
	}
	fmt.Fprintf(stderr, "Yadda saxlanan layihələr: %d · Kök qovluqlar: %s\n", len(st.Projects()), strings.Join(roots, ", "))
	return serve(ctx, c, m, token, stderr)
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

func serve(ctx context.Context, c config, b web.Backend, token string, stderr io.Writer) int {
	ln, port, err := web.Listen(c.addr, c.port)
	if err != nil {
		fmt.Fprintln(stderr, "depgate: port açılmadı:", err)
		return 1
	}
	srv := &web.Server{Token: token, B: b, AllowHosts: c.allowHost}
	url := fmt.Sprintf("http://127.0.0.1:%d/?t=%s", port, token)
	fmt.Fprintf(stderr, "\nDepGate: %s\nDayandırmaq üçün Ctrl+C\n", url)
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
			fmt.Fprintf(w, "  !!! ZƏRƏRLİ PAKET: %d — dərhal hesabata bax\n", s.Malware)
		}
		fmt.Fprintf(w, "  İndi et: kod dəyişmir %d · kod dəyişir %d · Planla %d · İstəyə görə %d · Lazım deyil %d\n", s.NowEasy, s.NowCode, s.Plan, s.Optional, s.OK)
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
			fmt.Fprintf(w, "  - Node: %s\n", strings.Join(p.Node.Why, "; "))
		}
		if len(p.Errors) > 0 {
			fmt.Fprintf(w, "  (%d xəbərdarlıq — interfeysdə bax)\n", len(p.Errors))
		}
	}
	for _, e := range rep.Errors {
		fmt.Fprintln(w, "xəbərdarlıq:", e)
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
			fmt.Fprintln(w, "Köhnə hesabat göndərildi:", e.Name())
		}
	}
}
