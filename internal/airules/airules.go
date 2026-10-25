// Package airules turns the exact versions a project uses into instructions for
// AI coding agents (AGENTS.md / CLAUDE.md / .cursor/rules), so they write code
// for the installed versions instead of the ones they were trained on.
//
// DepGate only shows these rules; it never writes them into the project.
// Rules are English on purpose: they end up in files agents read.
package airules

import (
	"sort"

	"github.com/Ali7Zeynalli/depgate/internal/report"
	"github.com/Ali7Zeynalli/depgate/internal/semver"
)

// stack lists the packages worth naming with their exact version.
var stack = map[string]string{
	"next": "https://nextjs.org/docs", "react": "https://react.dev/reference/react", "vue": "https://vuejs.org/guide/",
	"nuxt": "https://nuxt.com/docs", "@angular/core": "https://angular.dev", "svelte": "https://svelte.dev/docs",
	"@sveltejs/kit": "https://svelte.dev/docs/kit", "astro": "https://docs.astro.build", "react-native": "https://reactnative.dev/docs",
	"expo": "https://docs.expo.dev", "electron": "https://www.electronjs.org/docs", "@nestjs/core": "https://docs.nestjs.com",
	"express": "https://expressjs.com", "fastify": "https://fastify.dev/docs/latest/", "hono": "https://hono.dev/docs/",
	"typescript": "https://www.typescriptlang.org/docs/", "tailwindcss": "https://tailwindcss.com/docs", "eslint": "https://eslint.org/docs/latest/",
	"prisma": "https://www.prisma.io/docs", "drizzle-orm": "https://orm.drizzle.team/docs/overview", "typeorm": "https://typeorm.io",
	"mongoose": "https://mongoosejs.com/docs/", "sequelize": "https://sequelize.org/docs/", "zod": "https://zod.dev",
	"@tanstack/react-query": "https://tanstack.com/query/latest/docs", "react-router": "https://reactrouter.com", "react-router-dom": "https://reactrouter.com",
	"@reduxjs/toolkit": "https://redux-toolkit.js.org", "zustand": "https://zustand.docs.pmnd.rs", "@trpc/server": "https://trpc.io/docs",
	"graphql": "https://graphql.org/learn/", "@apollo/client": "https://www.apollographql.com/docs/react/", "socket.io": "https://socket.io/docs/v4/",
	"vite": "https://vite.dev/guide/", "vitest": "https://vitest.dev/guide/", "jest": "https://jestjs.io/docs/getting-started",
	"@playwright/test": "https://playwright.dev/docs/intro", "cypress": "https://docs.cypress.io", "storybook": "https://storybook.js.org/docs",
	"@mui/material": "https://mui.com/material-ui/", "antd": "https://ant.design/docs/react/introduce", "styled-components": "https://styled-components.com/docs",
	"next-intl": "https://next-intl.dev/docs", "i18next": "https://www.i18next.com", "better-auth": "https://www.better-auth.com/docs",
	"next-auth": "https://authjs.dev", "turbo": "https://turborepo.com/docs", "nx": "https://nx.dev/docs",
}

// rule applies to pkg versions in [min, max) (max "" = open).
type rule struct {
	pkg, min, max string
	topic         string
	texts         []string
	docs          string
}

var rules = []rule{
	{pkg: "next", min: "16.0.0", topic: "Next.js 16", docs: "https://nextjs.org/docs/app/guides/upgrading/version-16", texts: []string{
		"Request APIs are async only: `await cookies()`, `await headers()`, `await draftMode()`, and `params` / `searchParams` are Promises in pages, layouts, route handlers and metadata image functions.",
		"Use `proxy.ts` with `export function proxy()` instead of `middleware.ts` (middleware is deprecated; proxy runs on the Node.js runtime only).",
		"Turbopack is the default for `next dev` and `next build`; put its options in the top-level `turbopack` key of next.config, not `experimental.turbopack`.",
		"`next lint` is removed and `next build` no longer lints: run ESLint (flat config) or Biome directly.",
		"`revalidateTag(tag, profile)` needs a cacheLife profile as second argument (e.g. `'max'`); use `updateTag()` in Server Actions for read-your-writes.",
		"`serverRuntimeConfig` / `publicRuntimeConfig` and AMP are removed: use environment variables (`NEXT_PUBLIC_` for the client).",
		"Use `images.remotePatterns` (not `images.domains`) and `next/image` (not `next/legacy/image`).",
		"Parallel route slots need an explicit `default.js`.",
	}},
	{pkg: "next", min: "16.2.0", topic: "Next.js docs for agents", docs: "https://nextjs.org/docs/app/guides/ai-agents", texts: []string{
		"Version-matched Next.js docs ship in `node_modules/next/dist/docs/`; read them before relying on memory.",
	}},
	{pkg: "next", min: "15.0.0", max: "16.0.0", topic: "Next.js 15", docs: "https://nextjs.org/docs/app/guides/upgrading/version-15", texts: []string{
		"Treat `cookies()`, `headers()`, `draftMode()`, `params` and `searchParams` as async (`await` them); synchronous access only works temporarily and is removed in 16.",
		"`fetch` requests, GET route handlers and the client router cache are not cached by default; opt in explicitly.",
		"The App Router uses React 19.",
	}},
	{pkg: "next", min: "13.4.0", topic: "Next.js routing", docs: "https://nextjs.org/docs/app", texts: []string{
		"Use the App Router (`app/`) for new routes unless the project only uses `pages/`; do not mix the two for the same route.",
	}},
	{pkg: "react", min: "19.0.0", topic: "React 19", docs: "https://react.dev/blog/2024/04/25/react-19-upgrade-guide", texts: []string{
		"Pass `ref` as a regular prop; `forwardRef` is not needed for new components.",
		"Use `useActionState` (not `useFormState`), `useOptimistic` and `use()` where they fit; render `<Context>` directly instead of `<Context.Provider>`.",
		"`propTypes` and `defaultProps` on function components are removed: use TypeScript types and default parameters.",
		"`ReactDOM.render` / `hydrate` and string refs are removed: use `createRoot` / `hydrateRoot` and callback or object refs.",
	}},
	{pkg: "react", min: "18.0.0", max: "19.0.0", topic: "React 18", docs: "https://react.dev/blog/2022/03/08/react-18-upgrade-guide", texts: []string{
		"This project is on React 18: do not use React 19 APIs (`use()`, `useActionState`, `ref` as a prop without `forwardRef`, `<Context>` as provider).",
		"Mount with `createRoot`, not `ReactDOM.render`.",
	}},
	{pkg: "tailwindcss", min: "4.0.0", topic: "Tailwind CSS 4", docs: "https://tailwindcss.com/docs/upgrade-guide", texts: []string{
		"Configure in CSS: `@import \"tailwindcss\";` plus `@theme { ... }` for design tokens; a `tailwind.config.js` is not needed (load an old one only with `@config`).",
		"Use the `@tailwindcss/postcss` or `@tailwindcss/vite` plugin; `@tailwind base/components/utilities` directives are gone.",
	}},
	{pkg: "tailwindcss", min: "3.0.0", max: "4.0.0", topic: "Tailwind CSS 3", docs: "https://v3.tailwindcss.com/docs", texts: []string{
		"This project is on Tailwind 3: configure in `tailwind.config.js`; Tailwind 4 syntax (`@import \"tailwindcss\"`, `@theme`) does not work here.",
	}},
	{pkg: "eslint", min: "9.0.0", topic: "ESLint 9+", docs: "https://eslint.org/docs/latest/use/configure/migration-guide", texts: []string{
		"Use flat config (`eslint.config.js` / `.mjs` / `.ts`); do not create `.eslintrc*` files.",
	}},
	{pkg: "express", min: "5.0.0", topic: "Express 5", docs: "https://expressjs.com/en/guide/migrating-5.html", texts: []string{
		"Wildcards must be named (`/*splat`, `/{*splat}`) and optional parts use braces (`/users{/:id}`); `:param?` and regex characters in paths are invalid.",
		"Errors thrown or rejected in async handlers reach `next(err)` automatically; no wrapper needed.",
		"`req.body` is undefined without a body parser; `req.query` is read-only and uses the simple parser by default.",
		"Use `res.status(code).json(obj)`, `res.sendFile`, `app.delete`; `req.param()`, `app.del` and `res.redirect('back')` are removed.",
	}},
	{pkg: "express", min: "4.0.0", max: "5.0.0", topic: "Express 4", docs: "https://expressjs.com/en/4x/api.html", texts: []string{
		"This project is on Express 4: rejected promises in async handlers are NOT caught — pass errors to `next(err)` or wrap handlers; do not use Express 5 path syntax.",
	}},
	{pkg: "@nestjs/core", min: "11.0.0", topic: "NestJS 11", docs: "https://docs.nestjs.com/migration-guide", texts: []string{
		"Express 5 runs underneath: use named wildcards (`/*splat`, `forRoutes('{*splat}')`), not `*` or `(.*)`.",
		"Query strings use the simple parser (no nested objects) unless `app.set('query parser', 'extended')` is set.",
		"`CacheModule` uses Keyv stores (`stores: [...]`), not the old `store` option.",
		"Requires Node.js 20+.",
	}},
	{pkg: "prisma", min: "7.0.0", topic: "Prisma 7", docs: "https://www.prisma.io/docs/guides/upgrade-prisma-orm/v7", texts: []string{
		"Generator is `provider = \"prisma-client\"` with a required `output`; import the client from that path, not from `@prisma/client` in node_modules.",
		"Datasource URLs live in `prisma.config.ts`; every client needs a driver adapter (`new PrismaClient({ adapter })`).",
		"`.env` is not loaded automatically: load it yourself (e.g. `dotenv` or `node --env-file`).",
	}},
	{pkg: "zod", min: "4.0.0", topic: "Zod 4", docs: "https://zod.dev/v4/changelog", texts: []string{
		"Use top-level formats (`z.email()`, `z.uuid()`, `z.url()`) instead of `z.string().email()`.",
		"Customize errors with the `error` parameter (`message` is deprecated); use `z.strictObject()` / `z.looseObject()` instead of `.strict()` / `.passthrough()`; `z.record()` takes key and value schemas.",
	}},
	{pkg: "zod", min: "3.0.0", max: "4.0.0", topic: "Zod 3", docs: "https://v3.zod.dev", texts: []string{
		"This project is on Zod 3: use `z.string().email()` style; Zod 4 top-level formats like `z.email()` do not exist here.",
	}},
	{pkg: "@tanstack/react-query", min: "5.0.0", topic: "TanStack Query 5", docs: "https://tanstack.com/query/latest/docs/framework/react/guides/migrating-to-v5", texts: []string{
		"Hooks take one object: `useQuery({ queryKey, queryFn })`.",
		"`gcTime` (not `cacheTime`), `isPending` (not `isLoading` for the first load), `throwOnError` (not `useErrorBoundary`), `placeholderData: keepPreviousData` (not `keepPreviousData: true`).",
		"`useQuery` has no `onSuccess` / `onError` / `onSettled`; react to data in components or effects (mutations still have them).",
	}},
	{pkg: "react-router", min: "7.0.0", topic: "React Router 7", docs: "https://reactrouter.com/upgrading/v6", texts: []string{
		"Import from `react-router` (not `react-router-dom`).",
	}},
	{pkg: "typescript", min: "5.0.0", topic: "TypeScript 5", docs: "https://www.typescriptlang.org/docs/handbook/release-notes/overview.html", texts: []string{
		"Use `satisfies` for checked literals and standard (TC39) decorators unless `experimentalDecorators` is enabled in tsconfig (NestJS and TypeORM need it on).",
	}},
}

// replacement suggests a built-in or maintained alternative.
type replacement struct {
	pkg, use, why, docs string
	minNode             string // only when the project's Node is at least this
}

var replacements = []replacement{
	{pkg: "request", use: "global `fetch` (Node 18+) or `undici`", why: "request is deprecated since 2020 and gets no fixes", docs: "https://github.com/request/request/issues/3142"},
	{pkg: "request-promise", use: "global `fetch`", why: "built on the deprecated request package", docs: "https://github.com/request/request-promise"},
	{pkg: "request-promise-native", use: "global `fetch`", why: "built on the deprecated request package", docs: "https://github.com/request/request-promise-native"},
	{pkg: "node-fetch", use: "global `fetch`", why: "fetch is built into Node.js 18+", minNode: "18.0.0", docs: "https://nodejs.org/api/globals.html#fetch"},
	{pkg: "cross-fetch", use: "global `fetch`", why: "fetch is built into Node.js 18+ and browsers", minNode: "18.0.0", docs: "https://nodejs.org/api/globals.html#fetch"},
	{pkg: "isomorphic-fetch", use: "global `fetch`", why: "fetch is built into Node.js 18+ and browsers", minNode: "18.0.0", docs: "https://nodejs.org/api/globals.html#fetch"},
	{pkg: "moment", use: "`date-fns` or `dayjs`", why: "Moment.js is in maintenance mode and recommends alternatives", docs: "https://momentjs.com/docs/#/-project-status/"},
	{pkg: "uuid", use: "`crypto.randomUUID()` for v4 UUIDs", why: "built into Node.js and browsers; keep uuid for v1/v5/v7", docs: "https://nodejs.org/api/crypto.html#cryptorandomuuidoptions"},
	{pkg: "body-parser", use: "`express.json()` / `express.urlencoded()`", why: "Express ships these parsers itself", docs: "https://expressjs.com/en/api.html#express.json"},
	{pkg: "rimraf", use: "`fs.rm(path, { recursive: true, force: true })`", why: "built into Node.js 14.14+", docs: "https://nodejs.org/api/fs.html#fspromisesrmpath-options"},
	{pkg: "mkdirp", use: "`fs.mkdir(path, { recursive: true })`", why: "built into Node.js 10.12+", docs: "https://nodejs.org/api/fs.html#fspromisesmkdirpath-options"},
	{pkg: "dotenv", use: "`node --env-file=.env` or `process.loadEnvFile()`", why: "built into Node.js 20.6+ (loadEnvFile 21.7+); keep dotenv if a tool needs it", minNode: "20.6.0", docs: "https://nodejs.org/api/cli.html#--env-fileconfig"},
	{pkg: "tslint", use: "ESLint with `typescript-eslint`", why: "TSLint is deprecated since 2019", docs: "https://typescript-eslint.io/getting-started"},
	{pkg: "node-sass", use: "`sass`", why: "node-sass (LibSass) is deprecated", docs: "https://sass-lang.com/blog/libsass-is-deprecated/"},
	{pkg: "faker", use: "`@faker-js/faker`", why: "the original faker package was abandoned", docs: "https://fakerjs.dev"},
	{pkg: "colors", use: "`picocolors` or `util.styleText()`", why: "colors was sabotaged by its author in 2022 and is unmaintained", docs: "https://nodejs.org/api/util.html#utilstyletextformat-text-options"},
	{pkg: "querystring", use: "`URLSearchParams`", why: "a web standard built into Node.js and browsers", docs: "https://nodejs.org/api/url.html#class-urlsearchparams"},
	{pkg: "left-pad", use: "`String.prototype.padStart`", why: "built into JavaScript", docs: "https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String/padStart"},
	{pkg: "lodash.clonedeep", use: "`structuredClone()`", why: "built into Node.js 17+ and browsers (plain data only)", minNode: "17.0.0", docs: "https://developer.mozilla.org/docs/Web/API/Window/structuredClone"},
}

// nodeRules are hints about the runtime itself.
var nodeRules = []rule{
	{min: "18.0.0", topic: "Node.js runtime", docs: "https://nodejs.org/api/globals.html#fetch", texts: []string{"`fetch`, `AbortController`, `structuredClone` and `crypto.randomUUID()` are built in; do not add packages for them. Import core modules with the `node:` prefix."}},
	{min: "20.6.0", topic: "Node.js runtime", docs: "https://nodejs.org/api/cli.html#--env-fileconfig", texts: []string{"`node --env-file=.env` loads environment files; `node --test` is a built-in test runner and `node --watch` restarts on changes."}},
	{min: "22.12.0", topic: "Node.js runtime", docs: "https://nodejs.org/api/modules.html#loading-ecmascript-modules-using-require", texts: []string{"`require()` can load ES modules (synchronous ESM graphs) without flags."}},
}

// Build returns the rules for the given direct dependencies (name -> version)
// and Node.js version ("" when unknown). Nil when there is nothing to say.
func Build(deps map[string]string, nodeVersion string) *report.AIRules {
	out := &report.AIRules{Stack: []report.StackItem{}, Rules: []report.AIRule{}}
	names := make([]string, 0, len(deps))
	for n := range deps {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if docs, ok := stack[n]; ok {
			out.Stack = append(out.Stack, report.StackItem{Pkg: n, Version: deps[n], Docs: docs})
		}
	}
	for _, r := range rules {
		v, ok := deps[r.pkg]
		if !ok || !inRange(v, r.min, r.max) {
			continue
		}
		for _, t := range r.texts {
			out.Rules = append(out.Rules, report.AIRule{Topic: r.topic, Text: t, Docs: r.docs})
		}
	}
	if nodeVersion != "" {
		for _, r := range nodeRules {
			if inRange(nodeVersion, r.min, r.max) {
				for _, t := range r.texts {
					out.Rules = append(out.Rules, report.AIRule{Topic: r.topic + " " + nodeVersion, Text: t, Docs: r.docs})
				}
			}
		}
	}
	for _, r := range replacements {
		if _, ok := deps[r.pkg]; !ok {
			continue
		}
		if r.minNode != "" && (nodeVersion == "" || !inRange(nodeVersion, r.minNode, "")) {
			continue
		}
		out.Replace = append(out.Replace, report.Replacement{Pkg: r.pkg, Use: r.use, Why: r.why, Docs: r.docs})
	}
	if len(out.Stack) == 0 && len(out.Rules) == 0 && len(out.Replace) == 0 {
		return nil
	}
	return out
}

func inRange(v, min, max string) bool {
	x, err := semver.Parse(v)
	if err != nil {
		return false
	}
	if lo, err := semver.Parse(min); err == nil && semver.Less(x, lo) {
		return false
	}
	if max != "" {
		if hi, err := semver.Parse(max); err == nil && !semver.Less(x, hi) {
			return false
		}
	}
	return true
}
