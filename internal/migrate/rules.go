package migrate

import (
	"path"
	"regexp"
	"strings"

	"github.com/Ali7Zeynalli/depgate/internal/i18n"
	"github.com/Ali7Zeynalli/depgate/internal/report"
)

var (
	re     = regexp.MustCompile
	f      = i18n.F
	appDir = `(^|/)(src/)?app/`
	// Next.js app router files that receive params / searchParams
	nextRouteFile = re(appDir + `(.*/)?(page|layout|route|default|template|opengraph-image|twitter-image|icon|apple-icon)\.(j|t)sx?$`)
	nextConfig    = re(`(^|/)next\.config\.(m|c)?(j|t)s$`)
	pkgJSON       = re(`(^|/)package\.json$`)
	cssFile       = re(`\.(css|scss|sass|less|pcss)$`)
	scssFile      = re(`\.(scss|sass)$`)
	postcssConfig = re(`(^|/)postcss\.config\.(m|c)?(j|t)s$|(^|/)\.postcssrc(\.json)?$`)
	prismaSchema  = re(`(^|/)(prisma/)?schema\.prisma$|(^|/)prisma/schema/.*\.prisma$`)
	routeCall     = re("\\.(get|post|put|patch|delete|all|use|route|options|head)\\(\\s*['\"`]([^'\"`]+)['\"`]")
	appDirRe      = re(appDir)
	nestRoute     = re("@(Get|Post|Put|Patch|Delete|All|Options|Head|Controller)\\(\\s*['\"`]([^'\"`]*)['\"`]")
)

// badExpress5Path reports path syntax Express 5 (path-to-regexp v8) rejects.
func badExpress5Path(p string) bool {
	for i := 0; i < len(p); i++ {
		switch p[i] {
		case '*':
			// a named wildcard (*name) is fine
			if i+1 < len(p) && isIdent(p[i+1]) {
				continue
			}
			return true
		case '?', '(', ')', '[', ']', '+', '!':
			return true
		}
	}
	return false
}

func isIdent(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

var steps = []step{
	// ---------------- Next.js ----------------
	{pkg: "next", crosses: "15.0.0", topic: "Next.js 15", docs: "https://nextjs.org/docs/app/guides/upgrading/version-15",
		codemod: "npx @next/codemod@canary upgrade latest",
		checks: []i18n.T{
			f("fetch sorğuları, GET route handler-lər və client router cache artıq default olaraq keşlənmir — lazım olan yerdə cache: 'force-cache' və ya revalidate əlavə et", "fetch requests, GET route handlers and the client router cache are no longer cached by default — add cache: 'force-cache' or revalidate where you need it"),
			f("App Router React 19 tələb edir — React qrupunu da yenilə", "The App Router needs React 19 — update the React group too"),
		},
		patterns: []pattern{
			{id: "next15-sync-cookies", re: re(`\b(cookies|headers|draftMode)\(\)\s*\.`), msg: f("cookies() / headers() / draftMode() async oldu — əvvəl await et", "cookies() / headers() / draftMode() are async — await them first"), fix: "(await cookies()).get(…)"},
			{id: "next15-sync-params", path: nextRouteFile, re: re(`\b(searchParams|params)(\.[A-Za-z_$]|\[)`), msg: f("params / searchParams Promise oldu — `await props.params` ilə oxu", "params / searchParams are Promises — read them with `await props.params`"), fix: "const { slug } = await params"},
		}},
	{pkg: "next", crosses: "16.0.0", topic: "Next.js 16", docs: "https://nextjs.org/docs/app/guides/upgrading/version-16",
		codemod: "npx @next/codemod@canary upgrade latest",
		checks: []i18n.T{
			f("Node.js 20.9+ və TypeScript 5.1+ tələb olunur", "Requires Node.js 20.9+ and TypeScript 5.1+"),
			f("next dev və next build default olaraq Turbopack işlədir; xüsusi webpack konfiqi varsa build dayanır (--webpack ilə saxlaya bilərsən)", "next dev and next build use Turbopack by default; a custom webpack config stops the build (keep it with --webpack)"),
			f("next/image: default-lar dəyişib (minimumCacheTTL 4 saat, qualities [75], local IP bloklanır, maksimum 3 redirect)", "next/image defaults changed (minimumCacheTTL 4h, qualities [75], local IPs blocked, at most 3 redirects)"),
		},
		files: func(root string, files []string) []report.CodeHit {
			var out []report.CodeHit
			mw := re(`^(src/)?middleware\.(j|t)s$`)
			slots := map[string]bool{}
			hasDefault := map[string]bool{}
			for _, fl := range files {
				if mw.MatchString(fl) {
					out = append(out, fileHit(fl, "next16-middleware", f("middleware fayl adı deprecated-dir — proxy.ts adlandır və funksiyanı proxy kimi export et (proxy yalnız Node.js runtime-da işləyir; edge lazımdırsa middleware-də qal)", "The middleware file name is deprecated — rename to proxy.ts and export the function as proxy (proxy runs on Node.js only; stay on middleware if you need edge)"), "export function proxy(request) {}"))
				}
				if i := strings.Index(fl, "/@"); i >= 0 && appDirRe.MatchString(fl) {
					rest := fl[i+1:]
					slot := fl[:i+1] + strings.SplitN(rest, "/", 2)[0]
					slots[slot] = true
					if b := path.Base(fl); strings.HasPrefix(b, "default.") && path.Dir(fl) == slot {
						hasDefault[slot] = true
					}
				}
			}
			for s := range slots {
				if !hasDefault[s] {
					out = append(out, fileHit(s, "next16-parallel-default", f("Parallel route slot-unda default.js yoxdur — Next 16-da build alınmır", "This parallel route slot has no default.js — the Next 16 build fails"), "export default function Default() { return null }"))
				}
			}
			return out
		},
		patterns: []pattern{
			{id: "next16-next-lint", path: pkgJSON, re: re(`"[^"]+"\s*:\s*"[^"]*\bnext lint\b`), msg: f("next lint silinib və next build artıq lint etmir — ESLint və ya Biome-u birbaşa işlət", "next lint is removed and next build no longer lints — run ESLint or Biome directly"), fix: `"lint": "eslint ."`},
			{id: "next16-turbopack-flag", path: pkgJSON, re: re(`next (dev|build)[^"]*--turbo(pack)?\b`), msg: f("Turbopack artıq default-dur — --turbopack bayrağına ehtiyac yoxdur", "Turbopack is the default now — the --turbopack flag is not needed"), fix: `"dev": "next dev"`},
			{id: "next16-revalidate-tag", re: re(`\brevalidateTag\(\s*[^,()]+\)`), msg: f("revalidateTag ikinci arqument (cacheLife profili) tələb edir", "revalidateTag needs a second argument (a cacheLife profile)"), fix: "revalidateTag('posts', 'max')"},
			{id: "next16-runtime-config", re: re(`\b(serverRuntimeConfig|publicRuntimeConfig)\b|from ['"]next/config['"]`), msg: f("serverRuntimeConfig / publicRuntimeConfig silinib — environment dəyişənlərindən istifadə et (client üçün NEXT_PUBLIC_)", "serverRuntimeConfig / publicRuntimeConfig are removed — use environment variables (NEXT_PUBLIC_ for the client)"), fix: "process.env.NEXT_PUBLIC_API_URL"},
			{id: "next16-legacy-image", re: re(`from ['"]next/legacy/image['"]`), msg: f("next/legacy/image deprecated-dir", "next/legacy/image is deprecated"), fix: "import Image from 'next/image'"},
			{id: "next16-images-domains", path: nextConfig, re: re(`\bdomains\s*:`), msg: f("images.domains deprecated-dir — images.remotePatterns işlət", "images.domains is deprecated — use images.remotePatterns"), fix: "remotePatterns: [{ protocol: 'https', hostname: 'example.com' }]"},
			{id: "next16-amp", re: re(`from ['"]next/amp['"]|\bamp\s*:\s*(true|['"]hybrid['"])|\buseAmp\b`), msg: f("AMP dəstəyi silinib", "AMP support is removed"), fix: ""},
			{id: "next16-unstable-cache", re: re(`\bunstable_cache(Life|Tag)\b`), msg: f("cacheLife və cacheTag stabil oldu — unstable_ prefiksini sil", "cacheLife and cacheTag are stable — drop the unstable_ prefix"), fix: "import { cacheLife, cacheTag } from 'next/cache'"},
			{id: "next16-ppr-flags", re: re(`\bexperimental_ppr\b|\bdynamicIO\s*:|\buseCache\s*:|\bppr\s*:`), msg: f("PPR / dynamicIO / useCache eksperimental bayraqları silinib — cacheComponents-ə bax", "The PPR / dynamicIO / useCache experimental flags are removed — see cacheComponents"), fix: "cacheComponents: true"},
			{id: "next16-experimental-turbopack", path: nextConfig, re: re(`experimental\s*:\s*\{[^}]*\bturbopack\b|^\s*turbopack\s*:\s*\{`), ok: nil, msg: f("Turbopack seçimləri experimental-dan çıxıb — next.config-in yuxarı səviyyəsinə köçür (experimental.turbopack-dırsa)", "Turbopack options left experimental — move them to the top level of next.config (if they are under experimental.turbopack)"), fix: "turbopack: { … }"},
			{id: "next16-webpack-config", path: nextConfig, re: re(`\bwebpack\s*(:|\()`), msg: f("Xüsusi webpack konfiqi var — Turbopack default olduğu üçün next build dayanacaq; köçür və ya build-də --webpack istifadə et", "A custom webpack config exists — with Turbopack as default next build stops; migrate it or build with --webpack"), fix: `"build": "next build --webpack"`},
			{id: "next16-sass-tilde", path: scssFile, re: re(`@(import|use|forward)\s+['"]~`), msg: f("Turbopack Sass-da ~ prefiksini dəstəkləmir", "Turbopack does not support the ~ prefix in Sass imports"), fix: "@import 'bootstrap/dist/css/bootstrap.min.css';"},
			{id: "next16-sync-params", path: nextRouteFile, re: re(`\b(searchParams|params)(\.[A-Za-z_$]|\[)`), msg: f("Next 16-da params / searchParams-a sinxron müraciət tam silinib — await et", "Next 16 removes synchronous params / searchParams access entirely — await them"), fix: "const { slug } = await params"},
			{id: "next16-sync-cookies", re: re(`\b(cookies|headers|draftMode)\(\)\s*\.`), msg: f("Next 16-da cookies() / headers() / draftMode() yalnız async işləyir", "In Next 16 cookies() / headers() / draftMode() only work async"), fix: "(await cookies()).get(…)"},
		}},

	// ---------------- React ----------------
	{pkg: "react", crosses: "18.0.0", topic: "React 18", docs: "https://react.dev/blog/2022/03/08/react-18-upgrade-guide",
		patterns: []pattern{
			{id: "react18-render", re: re(`\bReactDOM\.(render|hydrate)\(|^\s*(render|hydrate)\(\s*<`), msg: f("ReactDOM.render React 18-də köhnəlib — createRoot işlət", "ReactDOM.render is legacy in React 18 — use createRoot"), fix: "createRoot(el).render(<App />)"},
		}},
	{pkg: "react", crosses: "19.0.0", topic: "React 19", docs: "https://react.dev/blog/2024/04/25/react-19-upgrade-guide",
		codemod: "npx codemod@latest react/19/migration-recipe && npx types-react-codemod@latest preset-19 ./src",
		checks:  []i18n.T{f("react-dom və @types/react da 19-a keçməlidir (Birlikdə yenilə kartı)", "react-dom and @types/react must move to 19 too (Update together card)")},
		patterns: []pattern{
			{id: "react19-render", re: re(`\bReactDOM\.(render|hydrate|unmountComponentAtNode|findDOMNode)\(|\b(unmountComponentAtNode|findDOMNode)\(`), msg: f("ReactDOM.render / hydrate / unmountComponentAtNode / findDOMNode React 19-da silinib", "ReactDOM.render / hydrate / unmountComponentAtNode / findDOMNode are removed in React 19"), fix: "createRoot(el).render(<App />)"},
			{id: "react19-proptypes", re: re(`\.(propTypes|defaultProps)\s*=`), msg: f("Funksiya komponentlərində propTypes və defaultProps silinib — TypeScript tipləri və default parametrlər işlət (class komponentlərdə defaultProps qalır)", "propTypes and defaultProps on function components are removed — use TypeScript types and default parameters (class components keep defaultProps)"), fix: "function Button({ size = 'md' }: Props)"},
			{id: "react19-string-ref", re: re(`\bref=["'][A-Za-z_]`), msg: f("String ref-lər silinib — callback və ya useRef işlət", "String refs are removed — use a callback ref or useRef"), fix: "ref={inputRef}"},
			{id: "react19-use-form-state", re: re(`\buseFormState\b`), msg: f("useFormState adı dəyişib: useActionState (react paketindən)", "useFormState is renamed to useActionState (from react)"), fix: "import { useActionState } from 'react'"},
			{id: "react19-test-utils", re: re(`from ['"]react-dom/test-utils['"]`), msg: f("react-dom/test-utils-dən act köçüb — react-dan import et", "act moved out of react-dom/test-utils — import it from react"), fix: "import { act } from 'react'"},
			{id: "react19-legacy-context", re: re(`\b(contextTypes|childContextTypes|getChildContext)\b`), msg: f("Köhnə (legacy) context API silinib — createContext işlət", "The legacy context API is removed — use createContext"), fix: "const Ctx = createContext(null)"},
			{id: "react19-create-factory", re: re(`\bcreateFactory\(`), msg: f("React.createFactory silinib — JSX işlət", "React.createFactory is removed — use JSX"), fix: ""},
			{id: "react19-test-renderer", re: re(`from ['"]react-test-renderer`), msg: f("react-test-renderer deprecated-dir — @testing-library/react-a keç", "react-test-renderer is deprecated — move to @testing-library/react"), fix: "import { render } from '@testing-library/react'"},
		}},

	// ---------------- TanStack Query ----------------
	{pkg: "@tanstack/react-query", crosses: "5.0.0", topic: "TanStack Query 5", docs: "https://tanstack.com/query/latest/docs/framework/react/guides/migrating-to-v5",
		checks: []i18n.T{
			f("isLoading-in mənası dəyişib: ilk yükləmə üçün isPending işlət", "isLoading changed meaning: use isPending for the first load"),
			f("useQuery-də onSuccess / onError / onSettled yoxdur (mutation-larda qalır)", "useQuery no longer has onSuccess / onError / onSettled (mutations keep them)"),
		},
		patterns: []pattern{
			{id: "tq5-positional", re: re(`\b(useQuery|useInfiniteQuery|useSuspenseQuery|prefetchQuery|fetchQuery|invalidateQueries|setQueryData|getQueryData)\(\s*[\['"]`), msg: f("Yalnız obyekt sintaksisi qalıb: useQuery({ queryKey, queryFn })", "Only the object syntax remains: useQuery({ queryKey, queryFn })"), fix: "useQuery({ queryKey: ['todos'], queryFn })"},
			{id: "tq5-cache-time", re: re(`\bcacheTime\b`), msg: f("cacheTime adı gcTime oldu", "cacheTime is renamed to gcTime"), fix: "gcTime: 5 * 60 * 1000"},
			{id: "tq5-error-boundary", re: re(`\buseErrorBoundary\s*:`), msg: f("useErrorBoundary adı throwOnError oldu", "useErrorBoundary is renamed to throwOnError"), fix: "throwOnError: true"},
			{id: "tq5-keep-previous", re: re(`\bkeepPreviousData\s*:\s*true\b|\bisPreviousData\b`), msg: f("keepPreviousData əvəzinə placeholderData: keepPreviousData; isPreviousData → isPlaceholderData", "Use placeholderData: keepPreviousData instead; isPreviousData → isPlaceholderData"), fix: "placeholderData: keepPreviousData"},
		}},

	// ---------------- ESLint ----------------
	{pkg: "eslint", crosses: "9.0.0", topic: "ESLint 9", docs: "https://eslint.org/docs/latest/use/configure/migration-guide",
		codemod: "npx @eslint/migrate-config .eslintrc.json",
		files: func(root string, files []string) []report.CodeHit {
			var out []report.CodeHit
			for _, fl := range files {
				if b := path.Base(fl); strings.HasPrefix(b, ".eslintrc") || b == ".eslintignore" {
					out = append(out, fileHit(fl, "eslint9-eslintrc", f("ESLint 9 flat config (eslint.config.js) istifadə edir; bu fayl artıq oxunmur", "ESLint 9 uses flat config (eslint.config.js); this file is no longer read"), "eslint.config.js"))
				}
			}
			return out
		},
		patterns: []pattern{
			{id: "eslint9-ext-flag", path: pkgJSON, re: re(`"[^"]+"\s*:\s*"[^"]*\beslint\b[^"]*--(ext|ignore-path|rulesdir)\b`), msg: f("--ext / --ignore-path / --rulesdir flat config-də yoxdur", "--ext / --ignore-path / --rulesdir do not exist with flat config"), fix: `"lint": "eslint ."`},
		}},

	// ---------------- Tailwind CSS ----------------
	{pkg: "tailwindcss", crosses: "4.0.0", topic: "Tailwind CSS 4", docs: "https://tailwindcss.com/docs/upgrade-guide",
		codemod: "npx @tailwindcss/upgrade",
		checks:  []i18n.T{f("Bəzi utility-lərin adı və default-ları dəyişib (shadow, rounded, blur, ring, border rəngi) — upgrade aləti çoxunu özü düzəldir", "Some utilities were renamed or changed defaults (shadow, rounded, blur, ring, border colour) — the upgrade tool fixes most of them")},
		files: func(root string, files []string) []report.CodeHit {
			var out []report.CodeHit
			cfg := re(`(^|/)tailwind\.config\.(m|c)?(j|t)s$`)
			for _, fl := range files {
				if cfg.MatchString(fl) {
					out = append(out, fileHit(fl, "tw4-config", f("Tailwind 4 konfiqi CSS-də saxlayır (@theme); JS konfiqi yalnız @config ilə yüklənir", "Tailwind 4 keeps config in CSS (@theme); a JS config only loads via @config"), `@config "./tailwind.config.js";`))
				}
			}
			return out
		},
		patterns: []pattern{
			{id: "tw4-directives", path: cssFile, re: re(`@tailwind\s+(base|components|utilities)`), msg: f("@tailwind direktivləri silinib", "@tailwind directives are removed"), fix: `@import "tailwindcss";`},
			{id: "tw4-postcss", path: postcssConfig, re: re(`['"]?tailwindcss['"]?\s*[:,)]|require\(['"]tailwindcss['"]\)`), msg: f("PostCSS plugini ayrı paketə köçüb", "The PostCSS plugin moved to its own package"), fix: `"@tailwindcss/postcss": {}`},
		}},

	// ---------------- Express ----------------
	{pkg: "express", crosses: "5.0.0", topic: "Express 5", docs: "https://expressjs.com/en/guide/migrating-5.html",
		codemod: "npx @expressjs/codemod upgrade",
		checks: []i18n.T{
			f("req.body body-parser olmadan undefined-dir; express.urlencoded() default olaraq extended: false", "req.body is undefined without a body parser; express.urlencoded() defaults to extended: false"),
			f("req.query sadə parser ilə oxunur və yazıla bilmir", "req.query uses the simple parser and is read-only"),
		},
		patterns: []pattern{
			{id: "express5-path", re: routeCall, ok: func(m []string) bool { return strings.HasPrefix(m[2], "/") && badExpress5Path(m[2]) }, msg: f("Express 5 yol sintaksisi: wildcard adlı olmalıdır (/*splat), optional hissə mötərizədə ({/:id}), regex simvolları qadağandır", "Express 5 path syntax: wildcards must be named (/*splat), optional parts use braces ({/:id}), regex characters are not allowed"), fix: "app.get('/*splat', …) · app.get('/users{/:id}', …)"},
			{id: "express5-catch-all", re: re("\\b(app|router)\\.(get|post|put|patch|delete|all|use)\\(\\s*['\"`]\\*['\"`]"), msg: f("Catch-all '*' Express 5-də işləmir — adlı wildcard işlət", "The catch-all '*' does not work in Express 5 — use a named wildcard"), fix: "app.get('/{*splat}', …)"},
			{id: "express5-del", re: re(`\b(app|router)\.del\(`), msg: f("app.del silinib", "app.del is removed"), fix: "app.delete(…)"},
			{id: "express5-sendfile", re: re(`\bres\.sendfile\(`), msg: f("res.sendfile silinib", "res.sendfile is removed"), fix: "res.sendFile(…)"},
			{id: "express5-req-param", re: re(`\breq\.param\(`), msg: f("req.param() silinib — req.params / req.body / req.query-ni açıq oxu", "req.param() is removed — read req.params / req.body / req.query explicitly"), fix: "req.params.id"},
			{id: "express5-status-args", re: re(`\bres\.(json|send|jsonp)\(\s*\d{3}\s*,|\bres\.(json|jsonp)\([^()]+,\s*\d{3}\s*\)`), msg: f("Status kodu arqument kimi verilmir", "The status code is no longer passed as an argument"), fix: "res.status(404).json(body)"},
			{id: "express5-redirect-back", re: re(`\bres\.(redirect|location)\(\s*['"]back['"]`), msg: f("'back' xüsusi dəyəri silinib", "The magic 'back' value is removed"), fix: "res.redirect(req.get('Referrer') || '/')"},
			{id: "express5-accepts-singular", re: re(`\breq\.accepts(Charset|Encoding|Language)\(`), msg: f("Tək formalı accepts* metodları silinib — cəm formalısını işlət", "The singular accepts* methods are removed — use the plural ones"), fix: "req.acceptsLanguages(…)"},
			{id: "express5-query-assign", re: re(`\breq\.query\s*=[^=]`), msg: f("req.query getter-dir, ona yazmaq xəta verir", "req.query is a getter; assigning to it throws"), fix: ""},
		}},

	// ---------------- NestJS ----------------
	{pkg: "@nestjs/core", crosses: "11.0.0", topic: "NestJS 11", docs: "https://docs.nestjs.com/migration-guide",
		checks: []i18n.T{
			f("Node.js 20+ tələb olunur", "Requires Node.js 20+"),
			f("Query string sadə parser ilə oxunur — nested obyektlər lazımdırsa app.set('query parser', 'extended')", "Query strings use the simple parser — set app.set('query parser', 'extended') if you need nested objects"),
			f("Destroy hook-ları (OnModuleDestroy və s.) indi tərs ardıcıllıqla işləyir", "Destroy hooks (OnModuleDestroy etc.) now run in reverse order"),
		},
		patterns: []pattern{
			{id: "nest11-for-routes", re: re("forRoutes\\(\\s*['\"`](\\*|[^'\"`]*\\(\\.\\*\\))['\"`]"), msg: f("Middleware wildcard-ı adlı olmalıdır", "Middleware wildcards must be named"), fix: "forRoutes('{*splat}')"},
			{id: "nest11-route-path", re: nestRoute, ok: func(m []string) bool { return badExpress5Path(m[2]) }, msg: f("Express 5 altında wildcard adlı olmalıdır (*splat) və optional hissə mötərizədə", "Under Express 5 wildcards must be named (*splat) and optional parts use braces"), fix: "@Get('files/*splat')"},
			{id: "nest11-cache-store", re: re(`\bstore\s*:\s*(redisStore|await redisStore)|from ['"]cache-manager-redis(-store|-yet)?['"]`), msg: f("CacheModule Keyv-ə keçib: store əvəzinə stores: [new KeyvRedis(…)]", "CacheModule moved to Keyv: use stores: [new KeyvRedis(…)] instead of store"), fix: "stores: [new KeyvRedis('redis://localhost:6379')]"},
		}},

	// ---------------- Zod ----------------
	{pkg: "zod", crosses: "4.0.0", topic: "Zod 4", docs: "https://zod.dev/v4/changelog",
		patterns: []pattern{
			{id: "zod4-string-format", re: re(`\bz\.string\(\)\.(email|uuid|url|cuid2?|ulid|ipv4|ipv6|base64|nanoid|emoji|jwt)\(`), msg: f("Format metodları deprecated-dir — yuxarı səviyyəli formatları işlət", "Format methods are deprecated — use the top-level formats"), fix: "z.email() · z.uuid() · z.url()"},
			{id: "zod4-error-params", re: re(`\b(invalid_type_error|required_error|errorMap)\s*:`), msg: f("invalid_type_error / required_error / errorMap əvəzinə error parametri", "Use the error parameter instead of invalid_type_error / required_error / errorMap"), fix: "z.string({ error: 'Required' })"},
			{id: "zod4-strict-passthrough", re: re(`\.(strict|passthrough)\(\)`), msg: f(".strict() / .passthrough() deprecated-dir", ".strict() / .passthrough() are deprecated"), fix: "z.strictObject({…}) · z.looseObject({…})"},
			{id: "zod4-merge", re: re(`\bz\.object\([^)]*\)\.merge\(|\w+Schema\.merge\(`), msg: f(".merge() deprecated-dir — .extend() və ya spread işlət", ".merge() is deprecated — use .extend() or spread"), fix: "A.extend(B.shape)"},
			{id: "zod4-record", re: re(`\bz\.record\(\s*z\.\w+\([^()]*\)\s*\)`), msg: f("z.record() iki arqument tələb edir (açar və dəyər)", "z.record() needs two arguments (key and value)"), fix: "z.record(z.string(), z.number())"},
			{id: "zod4-error-format", re: re(`\.(flatten|format)\(\)`), ok: nil, msg: f("ZodError.flatten() / .format() deprecated-dir — z.flattenError() / z.treeifyError() işlət (ZodError deyilsə nəzərə alma)", "ZodError.flatten() / .format() are deprecated — use z.flattenError() / z.treeifyError() (ignore if this is not a ZodError)"), fix: "z.treeifyError(err)"},
		}},

	// ---------------- Prisma ----------------
	{pkg: "prisma", crosses: "7.0.0", topic: "Prisma 7", docs: "https://www.prisma.io/docs/guides/upgrade-prisma-orm/v7",
		checks: []i18n.T{
			f("Node.js 20.19+ və TypeScript 5.4+ tələb olunur; package.json-da \"type\": \"module\"", "Requires Node.js 20.19+ and TypeScript 5.4+; set \"type\": \"module\" in package.json"),
			f(".env artıq avtomatik yüklənmir", ".env is no longer loaded automatically"),
		},
		patterns: []pattern{
			{id: "prisma7-generator", path: prismaSchema, re: re(`provider\s*=\s*"prisma-client-js"`), msg: f("Generator prisma-client oldu və output yolu məcburidir", "The generator is prisma-client now and output is required"), fix: `provider = "prisma-client"` + "\n  output   = \"../src/generated/prisma\""},
			{id: "prisma7-datasource-url", path: prismaSchema, re: re(`^\s*(url|directUrl|shadowDatabaseUrl)\s*=`), msg: f("Datasource URL-ləri prisma.config.ts-ə köçür", "Move datasource URLs to prisma.config.ts"), fix: "datasource: { url: env('DATABASE_URL') }"},
			{id: "prisma7-import", re: re(`from ['"]@prisma/client['"]`), msg: f("Client artıq node_modules-da yaranmır — generator output yolundan import et", "The client is no longer generated into node_modules — import from the generator output path"), fix: "import { PrismaClient } from './generated/prisma/client'"},
			{id: "prisma7-adapter", re: re(`new PrismaClient\(\s*\)`), msg: f("Hər client driver adapter tələb edir", "Every client needs a driver adapter"), fix: "new PrismaClient({ adapter: new PrismaPg({ connectionString }) })"},
		}},

	// ---------------- React Router ----------------
	{pkg: "react-router-dom", crosses: "7.0.0", topic: "React Router 7", docs: "https://reactrouter.com/upgrading/v6",
		patterns: []pattern{
			{id: "rr7-import", re: re(`from ['"]react-router-dom['"]`), msg: f("v7-də hər şey react-router paketindən import olunur", "In v7 everything is imported from react-router"), fix: "import { Link } from 'react-router'"},
		}},
	{pkg: "react-router-dom", crosses: "6.0.0", topic: "React Router 6", docs: "https://reactrouter.com/6.30.1/upgrading/v5",
		patterns: []pattern{
			{id: "rr6-switch", re: re(`\b(Switch|useHistory|withRouter|Redirect)\b`), msg: f("Switch → Routes, useHistory → useNavigate, Redirect → Navigate; withRouter silinib", "Switch → Routes, useHistory → useNavigate, Redirect → Navigate; withRouter is gone"), fix: "<Routes><Route path=… element={<Page />} /></Routes>"},
		}},
}

func init() {
	// official upgrade tools for frameworks that migrate themselves
	for _, x := range []struct{ pkg, topic, docs, cmd string }{
		{"@angular/core", "Angular", "https://angular.dev/update-guide", "ng update @angular/core@{major} @angular/cli@{major}"},
		{"nx", "Nx", "https://nx.dev/docs/guides/tips-n-tricks/advanced-update", "npx nx migrate {major} && npx nx migrate --run-migrations"},
		{"storybook", "Storybook", "https://storybook.js.org/docs/migration-guide", "npx storybook@{major} upgrade"},
		{"expo", "Expo SDK", "https://docs.expo.dev/workflow/upgrading-expo-sdk-walkthrough/", "npx expo install expo@^{major}.0.0 --fix"},
	} {
		for major := 2; major <= 40; major++ {
			steps = append(steps, step{pkg: x.pkg, crosses: itoa(major) + ".0.0", topic: x.topic + " " + itoa(major), docs: x.docs,
				codemod: strings.ReplaceAll(x.cmd, "{major}", itoa(major)),
				checks:  []i18n.T{f("Rəsmi upgrade aləti kodu və konfiqi özü yeniləyir; bir dəfəyə bir major keç", "The official upgrade tool updates code and config itself; move one major at a time")}})
		}
	}
}

func itoa(n int) string {
	if n < 10 {
		return string(rune('0' + n))
	}
	return itoa(n/10) + string(rune('0'+n%10))
}

// Topics lists the packages with curated migrations (for docs and tests).
func Topics() []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range steps {
		if !seen[s.pkg] {
			seen[s.pkg] = true
			out = append(out, s.pkg)
		}
	}
	return out
}
