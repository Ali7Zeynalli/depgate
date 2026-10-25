package migrate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for p, c := range files {
		full := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func hitRules(t *testing.T, p *Project, pkg, cur, to string) map[string][]string {
	t.Helper()
	m := p.For(pkg, cur, to)
	out := map[string][]string{}
	if m == nil {
		return out
	}
	n := 0
	for _, s := range m.Steps {
		for _, h := range s.Hits {
			out[h.Rule] = append(out[h.Rule], h.File+":"+itoa(h.Line))
			n++
			if h.Msg.Az == "" || h.Msg.En == "" {
				t.Errorf("%s: message not bilingual", h.Rule)
			}
		}
	}
	if n != m.Hits {
		t.Errorf("hit count %d != %d", m.Hits, n)
	}
	return out
}

func TestNext14To16(t *testing.T) {
	root := t.TempDir()
	write(t, root, map[string]string{
		"package.json":                 `{"scripts":{"dev":"next dev --turbopack","lint":"next lint"}}`,
		"middleware.ts":                "export function middleware() {}",
		"next.config.mjs":              "export default { images: { domains: ['a.com'] }, webpack: (c) => c }",
		"app/blog/[slug]/page.tsx":     "export default function Page({ params }) {\n  return <h1>{params.slug}</h1>\n}",
		"app/blog/[slug]/ok/page.tsx":  "export default async function Page(props) {\n  const { slug } = await props.params\n}",
		"app/actions.ts":               "import { cookies } from 'next/headers'\nconst t = cookies().get('t')\nrevalidateTag('posts')\nrevalidateTag('posts', 'max')",
		"app/@modal/(.)photo/page.tsx": "export default function P() {}",
		"app/@side/default.tsx":        "export default function D() { return null }",
		"app/@side/page.tsx":           "export default function S() {}",
		"lib/img.tsx":                  "import Image from 'next/legacy/image'\n// revalidateTag('commented')",
		"styles/a.scss":                "@import '~bootstrap/scss/bootstrap';",
		"node_modules/next/dist/x.js":  "cookies().get('x')",
		"packages/other/package.json":  "{}",
		"packages/other/src/x.ts":      "cookies().get('nested project')",
	})
	got := hitRules(t, Open(root), "next", "14.2.3", "16.0.3")
	want := map[string]int{
		"next16-middleware": 1, "next16-next-lint": 1, "next16-turbopack-flag": 1, "next16-images-domains": 1,
		"next16-webpack-config": 1, "next15-sync-params": 1, "next15-sync-cookies": 1, "next16-revalidate-tag": 1,
		"next16-parallel-default": 1, "next16-legacy-image": 1, "next16-sass-tilde": 1,
	}
	for r, n := range want {
		if len(got[r]) != n {
			t.Errorf("%s: got %v, want %d", r, got[r], n)
		}
	}
	for r := range got {
		if _, ok := want[r]; !ok {
			t.Errorf("unexpected %s: %v", r, got[r])
		}
	}
	if got["next16-parallel-default"][0] != "app/@modal:1" {
		t.Errorf("slot %v", got["next16-parallel-default"])
	}
	// 15 → 15.5 crosses nothing new
	if m := Open(root).For("next", "15.0.4", "15.5.6"); m != nil {
		t.Errorf("no breaking boundary crossed, got %+v", m)
	}
}

func TestReact19(t *testing.T) {
	root := t.TempDir()
	write(t, root, map[string]string{
		"src/index.jsx":  "ReactDOM.render(<App />, el)",
		"src/Button.tsx": "Button.defaultProps = { size: 'md' }\nconst [s, a] = useFormState(fn, 0)\n<input ref=\"name\" />\n<input ref={ref} />",
		"src/t.test.tsx": "import { act } from 'react-dom/test-utils'",
	})
	got := hitRules(t, Open(root), "react", "18.3.1", "19.2.0")
	for _, r := range []string{"react19-render", "react19-proptypes", "react19-use-form-state", "react19-string-ref", "react19-test-utils"} {
		if len(got[r]) != 1 {
			t.Errorf("%s: %v", r, got[r])
		}
	}
	m := Open(root).For("react", "18.3.1", "19.2.0")
	if m.Steps[0].Codemod == "" || !strings.HasPrefix(m.Steps[0].Docs, "https://react.dev/") {
		t.Fatalf("step %+v", m.Steps[0])
	}
}

func TestExpress5Paths(t *testing.T) {
	root := t.TempDir()
	write(t, root, map[string]string{"server.js": strings.Join([]string{
		"app.get('*', h)",
		"app.get('/files/*', h)",
		"router.get('/users/:id?', h)",
		"app.get('/ab(cd)?e', h)",
		"app.get('/*splat', h)",
		"app.get('/users{/:id}', h)",
		"app.get('/users/:id', h)",
		"app.use(express.json())",
		"res.json(obj, 404)",
		"res.send(201, body)",
		"app.del('/x', h)",
		"const v = req.param('id')",
		"res.redirect('back')",
		"req.query = {}",
		"if (req.query == null) {}",
	}, "\n")})
	got := hitRules(t, Open(root), "express", "4.21.2", "5.1.0")
	if n := len(got["express5-path"]); n != 3 { // '*' is not path-like ('/' prefix), '/files/*', '/users/:id?', '/ab(cd)?e'
		t.Errorf("paths: %v", got["express5-path"])
	}
	if len(got["express5-catch-all"]) != 1 {
		t.Errorf("catch-all: %v", got["express5-catch-all"])
	}
	for _, r := range []string{"express5-status-args", "express5-del", "express5-req-param", "express5-redirect-back", "express5-query-assign"} {
		if len(got[r]) == 0 {
			t.Errorf("%s missing", r)
		}
	}
	if len(got["express5-status-args"]) != 2 || len(got["express5-query-assign"]) != 1 {
		t.Errorf("status %v query %v", got["express5-status-args"], got["express5-query-assign"])
	}
}

func TestBadExpress5Path(t *testing.T) {
	for p, bad := range map[string]bool{"/*": true, "/*splat": false, "/{*splat}": false, "/:id?": true, "/a+b": true, "/users/:id": false, "/x{/:y}": false, "/(.*)": true} {
		if badExpress5Path(p) != bad {
			t.Errorf("%s: want %v", p, bad)
		}
	}
}

func TestOtherPackages(t *testing.T) {
	root := t.TempDir()
	write(t, root, map[string]string{
		".eslintrc.json":         "{}",
		"package.json":           `{"scripts":{"lint":"eslint src --ext .ts,.tsx"}}`,
		"src/app.css":            "@tailwind base;\n@tailwind utilities;",
		"postcss.config.js":      "module.exports = { plugins: { tailwindcss: {}, autoprefixer: {} } }",
		"tailwind.config.ts":     "export default {}",
		"src/q.ts":               "useQuery(['todos'], fetchTodos, { cacheTime: 1000, keepPreviousData: true })\nuseQuery({ queryKey: ['a'], queryFn })",
		"src/schema.ts":          "const s = z.string().email()\nconst o = z.object({}).strict()\nconst r = z.record(z.string())\nconst ok = z.record(z.string(), z.number())",
		"prisma/schema.prisma":   "generator client {\n  provider = \"prisma-client-js\"\n}\ndatasource db {\n  provider = \"postgresql\"\n  url = env(\"DATABASE_URL\")\n}",
		"src/db.ts":              "import { PrismaClient } from '@prisma/client'\nconst db = new PrismaClient()",
		"src/nest/app.module.ts": "consumer.apply(M).forRoutes('*')\n@Get('files/*')\n@Get('files/*splat')",
	})
	p := Open(root)
	cases := []struct {
		pkg, cur, to string
		rules        []string
	}{
		{"eslint", "8.57.0", "9.39.0", []string{"eslint9-eslintrc", "eslint9-ext-flag"}},
		{"tailwindcss", "3.4.17", "4.1.16", []string{"tw4-directives", "tw4-postcss", "tw4-config"}},
		{"@tanstack/react-query", "4.36.1", "5.90.0", []string{"tq5-positional", "tq5-cache-time", "tq5-keep-previous"}},
		{"zod", "3.25.0", "4.1.0", []string{"zod4-string-format", "zod4-strict-passthrough", "zod4-record"}},
		{"prisma", "6.19.0", "7.0.1", []string{"prisma7-generator", "prisma7-datasource-url", "prisma7-import", "prisma7-adapter"}},
		{"@nestjs/core", "10.4.0", "11.1.6", []string{"nest11-for-routes", "nest11-route-path"}},
	}
	for _, c := range cases {
		got := hitRules(t, p, c.pkg, c.cur, c.to)
		for _, r := range c.rules {
			if len(got[r]) == 0 {
				t.Errorf("%s: %s missing (got %v)", c.pkg, r, got)
			}
		}
	}
	if got := hitRules(t, p, "zod", "3.25.0", "4.1.0"); len(got["zod4-record"]) != 1 || len(got["tq5-positional"]) != 0 {
		t.Errorf("zod record %v", got["zod4-record"])
	}
	if got := hitRules(t, p, "@nestjs/core", "10.4.0", "11.1.6"); len(got["nest11-route-path"]) != 1 {
		t.Errorf("nest route %v", got["nest11-route-path"])
	}
}

func TestCodemodOnly(t *testing.T) {
	m := Open(t.TempDir()).For("@angular/core", "18.2.0", "20.1.0")
	if m == nil || len(m.Steps) != 2 || m.Steps[1].Codemod != "ng update @angular/core@20 @angular/cli@20" {
		t.Fatalf("%+v", m)
	}
}

func TestStepsWellFormed(t *testing.T) {
	for _, s := range steps {
		if s.pkg == "" || s.topic == "" || !strings.HasPrefix(s.docs, "https://") {
			t.Errorf("step %+v", s.topic)
		}
		for _, c := range s.checks {
			if c.Az == "" || c.En == "" {
				t.Errorf("%s: check not bilingual", s.topic)
			}
		}
		for _, p := range s.patterns {
			if p.id == "" || p.re == nil || p.msg.Az == "" || p.msg.En == "" {
				t.Errorf("%s: bad pattern %q", s.topic, p.id)
			}
		}
	}
}
