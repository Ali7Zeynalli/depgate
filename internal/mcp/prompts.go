package mcp

import (
	"errors"
	"strings"
)

// Prompts are ready-made tasks the user picks in the agent (Claude Code shows
// them as /mcp__depgate__<name>), so it is visible what DepGate can do.
type prompt struct {
	title, desc string
	args        []promptArg
	text        func(a map[string]string) string
}

type promptArg struct {
	name, desc string
	required   bool
}

var promptOrder = []string{"fix", "status", "check", "docker", "changes"}

var prompts = map[string]prompt{
	"fix": {
		title: "Fix dependencies with DepGate",
		desc:  "Shows a checklist by category, asks which to do, then fixes them one by one; DepGate verifies each task with a new scan.",
		args:  []promptArg{{name: "project", desc: "Project path or name (default: the current one)"}},
		text: func(a map[string]string) string {
			return "Fix the dependencies of " + projectOf(a) + " with DepGate, step by step.\n" +
				"1. Call get_overview and show me the checklist exactly. Ask me which tasks to do. Do not change anything before I answer.\n" +
				"2. Call start_tasks with the ids I chose.\n" +
				"3. For each task in order: call get_task, do only that task (for code changes call get_code_changes and check the places, they are approximate), install, build and test, then call complete_task.\n" +
				"4. Tell me what DepGate verified after each task — done, partly done or not done — not your own guess.\n" +
				"Before adding any new package, call check_package. Leave accepted risks and tasks I did not choose alone."
		},
	},
	"status": {
		title: "DepGate status",
		desc:  "What DepGate says about this project right now, in a few lines.",
		args:  []promptArg{{name: "project", desc: "Project path or name (default: the current one)"}},
		text: func(a map[string]string) string {
			return "Call DepGate's project_status for " + projectOf(a) + " and tell me in a few lines: malware, what to update now, what needs code changes, Node.js, Docker and web server. Then say what you would do first."
		},
	},
	"check": {
		title: "Check a package before installing",
		desc:  "Is this package (and version) safe for this project, and which version to install.",
		args: []promptArg{{name: "package", desc: "Package name, e.g. lodash", required: true},
			{name: "version", desc: "Version or range (default: latest)"}},
		text: func(a map[string]string) string {
			spec := a["package"]
			if v := strings.TrimSpace(a["version"]); v != "" {
				spec += "@" + v
			}
			return "Call DepGate's check_package for " + spec + " in " + projectOf(a) + ". Tell me if it is safe, why, and the exact install command. Do not install it unless the verdict is ok and I confirm."
		},
	},
	"docker": {
		title: "Review Docker and web server",
		desc:  "Dockerfile, compose, image, nginx and Caddy findings explained, with the lines to change.",
		args:  []promptArg{{name: "project", desc: "Project path or name (default: the current one)"}},
		text: func(a map[string]string) string {
			return "Call DepGate's get_docker_issues for " + projectOf(a) + ". Explain each high and medium finding in one line and show the line to change. Do not edit files until I agree."
		},
	},
	"changes": {
		title: "What changed since the last scan",
		desc:  "New, fixed and changed findings between the recent scans.",
		args:  []promptArg{{name: "project", desc: "Project path or name (default: the current one)"}},
		text: func(a map[string]string) string {
			return "Call DepGate's get_history for " + projectOf(a) + " and tell me what is new, what was fixed and whether the lockfile changed or new advisories appeared."
		},
	},
}

func projectOf(a map[string]string) string {
	if p := strings.TrimSpace(a["project"]); p != "" {
		return "the project " + p
	}
	return "the project in the current working directory (pass its absolute path as \"project\" when a tool asks for it)"
}

func promptList() []any {
	out := make([]any, 0, len(promptOrder))
	for _, n := range promptOrder {
		p := prompts[n]
		args := make([]any, 0, len(p.args))
		for _, a := range p.args {
			args = append(args, map[string]any{"name": a.name, "description": a.desc, "required": a.required})
		}
		out = append(out, map[string]any{"name": n, "title": p.title, "description": p.desc, "arguments": args})
	}
	return out
}

func getPrompt(name string, args map[string]string) (any, error) {
	p, ok := prompts[name]
	if !ok {
		return nil, errors.New("unknown prompt: " + name)
	}
	if args == nil {
		args = map[string]string{}
	}
	for _, a := range p.args {
		if a.required && strings.TrimSpace(args[a.name]) == "" {
			return nil, errors.New("missing argument: " + a.name)
		}
	}
	return map[string]any{
		"description": p.desc,
		"messages":    []any{map[string]any{"role": "user", "content": map[string]any{"type": "text", "text": p.text(args)}}},
	}, nil
}
