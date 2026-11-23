package images

import (
	"context"
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/Ali7Zeynalli/depgate/internal/report"
	"github.com/Ali7Zeynalli/depgate/internal/sources"
)

// ResolveOS finds the OS release of images whose tag does not say it (node:22,
// postgres:16, redis:7.4-alpine): it reads the image's config from Docker Hub
// (the build history names the Debian release or the Alpine minirootfs; Ubuntu
// images carry a version label). Nothing is pulled; only the small manifest and
// config documents are read, cached for a day. Images on other registries, and
// lookups that fail, keep what the tag said.
func ResolveOS(ctx context.Context, f sources.Fetcher, items []report.ImageItem, max int) []report.ImageItem {
	if max <= 0 {
		max = 20
	}
	known := map[string][2]string{}
	asked := 0
	for i := range items {
		it := &items[i]
		if it.OSVersion != "" || it.Unpinned || strings.Contains(it.Image, "@") {
			continue
		}
		repo, tag, ok := hubRef(it.Image)
		if !ok {
			continue
		}
		key := repo + ":" + tag
		r, done := known[key]
		if !done {
			if asked >= max {
				continue
			}
			asked++
			osName, ver, err := hubOS(ctx, f, repo, tag)
			if err != nil {
				osName, ver = "", ""
			}
			r = [2]string{osName, ver}
			known[key] = r
		}
		if r[0] != "" && r[1] != "" {
			it.OS, it.OSVersion, it.OSGuess, it.OSFrom = r[0], r[1], false, "registry"
		}
	}
	return items
}

// hubRef turns an image reference into a Docker Hub repository and tag.
func hubRef(ref string) (repo, tag string, ok bool) {
	name := ref
	if i := strings.LastIndex(name, ":"); i > strings.LastIndex(name, "/") {
		name, tag = name[:i], name[i+1:]
	}
	if tag == "" || tag == "latest" {
		return "", "", false
	}
	parts := strings.Split(name, "/")
	if len(parts) > 1 && (strings.ContainsAny(parts[0], ".:") || parts[0] == "localhost") {
		if parts[0] != "docker.io" && parts[0] != "index.docker.io" && parts[0] != "registry-1.docker.io" {
			return "", "", false // another registry
		}
		parts = parts[1:]
	}
	if len(parts) == 1 {
		parts = []string{"library", parts[0]}
	}
	repo = strings.ToLower(strings.Join(parts, "/"))
	return repo, tag, repo != "" && !strings.ContainsAny(repo+tag, "$ {}")
}

const (
	hubAuth     = "https://auth.docker.io/token"
	hubRegistry = "https://registry-1.docker.io/v2/"
)

var (
	debianRe = regexp.MustCompile(`debian\.sh --arch '[a-z0-9]+' out/ '([a-z]+)'`)
	alpineRe = regexp.MustCompile(`alpine-minirootfs-(\d+\.\d+)`)
)

func hubOS(ctx context.Context, f sources.Fetcher, repo, tag string) (string, string, error) {
	b, err := f.Do(ctx, "GET", hubAuth+"?service=registry.docker.io&scope=repository:"+url.QueryEscape(repo)+":pull", nil, nil, 4*time.Minute)
	if err != nil {
		return "", "", err
	}
	var tok struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(b, &tok); err != nil || tok.Token == "" {
		return "", "", err
	}
	h := map[string]string{"Authorization": "Bearer " + tok.Token,
		"Accept": "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json"}
	get := func(path string, v any) error {
		b, err := f.Do(ctx, "GET", hubRegistry+repo+path, nil, h, 24*time.Hour)
		if err != nil {
			return err
		}
		return json.Unmarshal(b, v)
	}
	var m struct {
		Manifests []struct {
			Digest   string `json:"digest"`
			Platform struct {
				OS   string `json:"os"`
				Arch string `json:"architecture"`
			} `json:"platform"`
		} `json:"manifests"`
		Config struct {
			Digest string `json:"digest"`
		} `json:"config"`
	}
	if err := get("/manifests/"+url.PathEscape(tag), &m); err != nil {
		return "", "", err
	}
	if m.Config.Digest == "" && len(m.Manifests) > 0 { // an index: the linux/amd64 image
		d := ""
		for _, x := range m.Manifests {
			if x.Platform.OS == "linux" && x.Platform.Arch == "amd64" {
				d = x.Digest
				break
			}
		}
		if d == "" {
			d = m.Manifests[0].Digest
		}
		m.Manifests = nil
		if err := get("/manifests/"+d, &m); err != nil {
			return "", "", err
		}
	}
	if m.Config.Digest == "" {
		return "", "", nil
	}
	var cfg struct {
		Config struct {
			Labels map[string]string `json:"Labels"`
		} `json:"config"`
		History []struct {
			CreatedBy string `json:"created_by"`
		} `json:"history"`
	}
	if err := get("/blobs/"+m.Config.Digest, &cfg); err != nil {
		return "", "", err
	}
	osName, ver := osFromConfig(cfg.Config.Labels, cfg.History)
	return osName, ver, nil
}

func osFromConfig(labels map[string]string, history []struct {
	CreatedBy string `json:"created_by"`
}) (string, string) {
	for _, h := range history {
		if m := debianRe.FindStringSubmatch(h.CreatedBy); m != nil {
			if c, ok := codenames[m[1]]; ok {
				return c[0], c[1]
			}
		}
		if m := alpineRe.FindStringSubmatch(h.CreatedBy); m != nil {
			return "alpine", m[1]
		}
	}
	if v := labels["org.opencontainers.image.version"]; regexp.MustCompile(`^\d\d\.\d\d$`).MatchString(v) &&
		strings.Contains(strings.ToLower(labels["org.opencontainers.image.ref.name"]+labels["org.opencontainers.image.title"]), "ubuntu") {
		return "ubuntu", v
	}
	for _, h := range history { // images built FROM ubuntu keep its label line in the history
		if m := regexp.MustCompile(`org\.opencontainers\.image\.version=(\d\d\.\d\d)`).FindStringSubmatch(h.CreatedBy); m != nil && strings.Contains(h.CreatedBy, "ubuntu") {
			return "ubuntu", m[1]
		}
	}
	return "", ""
}
