package sources

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

// PkgVersion is one published version with what DepGate needs to choose targets.
type PkgVersion struct {
	Version    string
	Published  time.Time
	Deprecated bool
	Reason     string
}

// PkgInfo lists all versions of a package (from deps.dev).
type PkgInfo struct {
	Name     string
	Versions []PkgVersion
	Default  string // dist-tag latest
}

// Package loads the version list of an npm package from deps.dev (no auth).
func Package(ctx context.Context, f Fetcher, name string) (*PkgInfo, error) {
	u := "https://api.deps.dev/v3/systems/npm/packages/" + url.PathEscape(name)
	b, err := f.Do(ctx, "GET", u, nil, nil, time.Hour)
	if err != nil {
		if !errors.Is(err, ErrNotFound) && ctx.Err() == nil {
			// deps.dev down or blocked: fall back to the npm registry (no publish dates)
			if pi, ferr := packageFromRegistry(ctx, f, name); ferr == nil {
				return pi, nil
			}
		}
		return nil, fmt.Errorf("deps.dev %s: %w", name, err)
	}
	var doc struct {
		Versions []struct {
			VersionKey struct {
				Version string `json:"version"`
			} `json:"versionKey"`
			PublishedAt      string `json:"publishedAt"`
			IsDefault        bool   `json:"isDefault"`
			IsDeprecated     bool   `json:"isDeprecated"`
			DeprecatedReason string `json:"deprecatedReason"`
		} `json:"versions"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("deps.dev %s: %w", name, err)
	}
	pi := &PkgInfo{Name: name}
	for _, v := range doc.Versions {
		t, _ := time.Parse(time.RFC3339, v.PublishedAt)
		pi.Versions = append(pi.Versions, PkgVersion{Version: v.VersionKey.Version, Published: t, Deprecated: v.IsDeprecated, Reason: v.DeprecatedReason})
		if v.IsDefault {
			pi.Default = v.VersionKey.Version
		}
	}
	return pi, nil
}

// Manifest is one version document from the npm registry (small: /<name>/<version>).
type Manifest struct {
	Name       string            `json:"name"`
	Version    string            `json:"version"`
	Scripts    map[string]string `json:"scripts"`
	Deprecated string            `json:"deprecated"`
	Engines    map[string]string `json:"-"`
	RawEngines json.RawMessage   `json:"engines"`
	Peer       map[string]string `json:"peerDependencies"`
	Deps       map[string]string `json:"dependencies"`
	NpmUser    struct {
		Name string `json:"name"`
	} `json:"_npmUser"`
	Repository json.RawMessage `json:"repository"`
	Dist       struct {
		Attestations *struct {
			URL string `json:"url"`
		} `json:"attestations"`
	} `json:"dist"`
}

// InstallScripts lists lifecycle scripts that run on install.
func (m *Manifest) InstallScripts() []string {
	var out []string
	for _, k := range []string{"preinstall", "install", "postinstall"} {
		if strings.TrimSpace(m.Scripts[k]) != "" {
			out = append(out, k)
		}
	}
	return out
}

// HasProvenance reports whether the version carries an npm provenance attestation.
func (m *Manifest) HasProvenance() bool { return m.Dist.Attestations != nil }

// RepoURL returns the declared repository URL ("" when missing).
func (m *Manifest) RepoURL() string {
	if len(m.Repository) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(m.Repository, &s) == nil {
		return s
	}
	var o struct {
		URL string `json:"url"`
	}
	_ = json.Unmarshal(m.Repository, &o)
	return o.URL
}

// Version loads one version document from registry.npmjs.org.
func Version(ctx context.Context, f Fetcher, name, version string) (*Manifest, error) {
	u := "https://registry.npmjs.org/" + strings.Replace(url.PathEscape(name), "%40", "@", 1) + "/" + url.PathEscape(version)
	b, err := f.Do(ctx, "GET", u, nil, nil, 30*24*time.Hour) // a published version never changes (except deprecation)
	if err != nil {
		return nil, fmt.Errorf("npm %s@%s: %w", name, version, err)
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("npm %s@%s: %w", name, version, err)
	}
	m.Engines = map[string]string{}
	_ = json.Unmarshal(m.RawEngines, &m.Engines) // engines is sometimes an array in old packages
	return &m, nil
}

// packageFromRegistry reads the abbreviated npm packument (versions, dist-tags,
// deprecation). It has no publish dates, so cooldown checks are skipped.
func packageFromRegistry(ctx context.Context, f Fetcher, name string) (*PkgInfo, error) {
	u := "https://registry.npmjs.org/" + strings.Replace(url.PathEscape(name), "%40", "@", 1)
	b, err := f.Do(ctx, "GET", u, nil, map[string]string{"Accept": "application/vnd.npm.install-v1+json"}, time.Hour)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Tags     map[string]string `json:"dist-tags"`
		Versions map[string]struct {
			Deprecated string `json:"deprecated"`
		} `json:"versions"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	pi := &PkgInfo{Name: name, Default: doc.Tags["latest"]}
	for v, x := range doc.Versions {
		pi.Versions = append(pi.Versions, PkgVersion{Version: v, Deprecated: x.Deprecated != "", Reason: x.Deprecated})
	}
	sort.Slice(pi.Versions, func(i, j int) bool { return pi.Versions[i].Version < pi.Versions[j].Version })
	return pi, nil
}
