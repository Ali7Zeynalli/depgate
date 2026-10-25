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
	"time"

	"github.com/Ali7Zeynalli/depgate/internal/project"
	"github.com/Ali7Zeynalli/depgate/internal/report"
	"github.com/Ali7Zeynalli/depgate/internal/scan"
	"github.com/Ali7Zeynalli/depgate/internal/sources"
	"github.com/Ali7Zeynalli/depgate/internal/web"
)

var version = "0.1.0-dev" // set by goreleaser: -ldflags "-X main.version=..."

type config struct {
	port     int
	noOpen   bool
	offline  bool
	depth    int
	jsonOut  bool
	ci       bool
	failOn   string
	cooldown int
	push     string
	token    string
	version  bool
	view     string
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	var c config
	fs := flag.NewFlagSet("depgate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.IntVar(&c.port, "port", 7777, "veb interfeysin portu")
	fs.BoolVar(&c.noOpen, "no-open", false, "brauzeri avtomatik açma")
	fs.BoolVar(&c.offline, "offline", false, "şəbəkəyə çıxma, yalnız keşdən istifadə et")
	fs.IntVar(&c.depth, "depth", 3, "layihə axtarışının dərinliyi")
	fs.BoolVar(&c.jsonOut, "json", false, "hesabatı JSON kimi stdout-a yaz, interfeys açma")
	fs.BoolVar(&c.ci, "ci", false, "CI rejimi: mətn xülasəsi və çıxış kodu")
	fs.StringVar(&c.failOn, "fail-on", "high", "CI-da bu səviyyədən (critical|high|moderate|low) uğursuz ol")
	fs.IntVar(&c.cooldown, "cooldown", 3, "bundan cavan versiyaları (gün) hədəf seçmə")
	fs.StringVar(&c.push, "push", "", "hesabatı bu URL-ə POST et")
	fs.StringVar(&c.token, "token", os.Getenv("DEPGATE_PUSH_TOKEN"), "--push üçün Bearer token (və ya DEPGATE_PUSH_TOKEN)")
	fs.BoolVar(&c.version, "version", false, "versiyanı göstər")
	fs.StringVar(&c.view, "view", "", "saxlanmış JSON hesabatı (--json çıxışı) interfeysdə aç, skan etmə")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "DepGate %s — Node.js layihələri üçün paket təhlükəsizliyi və yeniləmələr\n\n", version)
		fmt.Fprintln(stderr, "İstifadə:\n  depgate [bayraqlar] [qovluq]\n\nNümunələr:\n  depgate                 bu qovluğu skan et və brauzerdə aç\n  depgate ~/projects      bütün alt layihələri skan et\n  depgate --json > r.json\n  depgate --ci --fail-on high\n\nBayraqlar:")
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
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		return serve(ctx, c, &rep, nil, stderr)
	}
	root := "."
	if fs.NArg() > 0 {
		root = fs.Arg(0)
	}
	if fs.NArg() > 1 {
		fmt.Fprintln(stderr, "depgate: yalnız bir qovluq ver")
		return 2
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	cacheDir := ""
	if d, err := os.UserCacheDir(); err == nil {
		cacheDir = filepath.Join(d, "depgate")
	}
	quiet := c.jsonOut
	opt := scan.Options{Version: version, CooldownDays: c.cooldown, Offline: c.offline, Progress: func(s string) {
		if !quiet {
			fmt.Fprintln(stderr, s)
		}
	}}
	doScan := func() *report.Report {
		f := sources.NewHTTP(cacheDir, c.offline, version)
		opt.Now = time.Now()
		return scan.Run(ctx, f, dirs, opt)
	}

	if c.push != "" {
		flushOutbox(ctx, cacheDir, c.push, c.token, stderr)
	}
	rep := doScan()
	if ctx.Err() != nil {
		return 130
	}
	if c.push != "" {
		if err := push(ctx, c.push, c.token, rep); err != nil {
			fmt.Fprintln(stderr, "depgate: göndərilmədi, növbəti dəfə təkrar ediləcək:", err)
			saveOutbox(cacheDir, rep)
		} else if !quiet {
			fmt.Fprintln(stderr, "Hesabat göndərildi:", c.push)
		}
	}

	switch {
	case c.jsonOut:
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			return 1
		}
		return exitCode(rep, c)
	case c.ci:
		printSummary(stderr, rep)
		return exitCode(rep, c)
	}

	printSummary(stderr, rep)
	return serve(ctx, c, rep, doScan, stderr)
}

func serve(ctx context.Context, c config, rep *report.Report, rescan func() *report.Report, stderr io.Writer) int {
	ln, port, err := web.Listen(c.port)
	if err != nil {
		fmt.Fprintln(stderr, "depgate: port açılmadı:", err)
		return 1
	}
	srv := &web.Server{Token: web.NewToken(), Rescan: rescan}
	srv.Set(rep)
	url := fmt.Sprintf("http://127.0.0.1:%d/?t=%s", port, srv.Token)
	fmt.Fprintf(stderr, "\nHesabat: %s\nDayandırmaq üçün Ctrl+C\n", url)
	if !c.noOpen {
		openBrowser(url)
	}
	hs := &http.Server{Handler: srv.Handler(port), ReadHeaderTimeout: 10 * time.Second}
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
