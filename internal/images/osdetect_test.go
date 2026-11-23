package images

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Ali7Zeynalli/depgate/internal/report"
)

type hubFake struct{ calls []string }

func (h *hubFake) Do(_ context.Context, _, u string, _ []byte, hd map[string]string, _ time.Duration) ([]byte, error) {
	h.calls = append(h.calls, u)
	switch {
	case strings.HasPrefix(u, hubAuth):
		return []byte(`{"token":"t"}`), nil
	case hd["Authorization"] != "Bearer t":
		return nil, errors.New("no token")
	case strings.HasSuffix(u, "library/node/manifests/22"):
		return []byte(`{"manifests":[{"digest":"sha256:arm","platform":{"os":"linux","architecture":"arm64"}},{"digest":"sha256:amd","platform":{"os":"linux","architecture":"amd64"}}]}`), nil
	case strings.HasSuffix(u, "library/node/manifests/sha256:amd"):
		return []byte(`{"config":{"digest":"sha256:cfg1"}}`), nil
	case strings.HasSuffix(u, "/blobs/sha256:cfg1"):
		return []byte(`{"history":[{"created_by":"# debian.sh --arch 'amd64' out/ 'trixie' '@1760000000'"},{"created_by":"ENV NODE_VERSION=22"}]}`), nil
	case strings.HasSuffix(u, "library/redis/manifests/7.4-alpine"):
		return []byte(`{"config":{"digest":"sha256:cfg2"}}`), nil
	case strings.HasSuffix(u, "/blobs/sha256:cfg2"):
		return []byte(`{"history":[{"created_by":"ADD alpine-minirootfs-3.21.2-x86_64.tar.gz / # buildkit"}]}`), nil
	case strings.HasSuffix(u, "library/ubuntu/manifests/rolling"):
		return []byte(`{"config":{"digest":"sha256:cfg3"}}`), nil
	case strings.HasSuffix(u, "/blobs/sha256:cfg3"):
		return []byte(`{"config":{"Labels":{"org.opencontainers.image.ref.name":"ubuntu","org.opencontainers.image.version":"26.04"}}}`), nil
	}
	return nil, errors.New("404")
}

func TestResolveOS(t *testing.T) {
	f := &hubFake{}
	in := []report.ImageItem{
		{Image: "node:22", OS: "debian", OSGuess: true},
		{Image: "node:22", OS: "debian", OSGuess: true}, // asked once
		{Image: "redis:7.4-alpine", OS: "alpine"},
		{Image: "ubuntu:rolling"},
		{Image: "ghcr.io/acme/api:1.0"},                                // another registry: not asked
		{Image: "postgres:16-bookworm", OS: "debian", OSVersion: "12"}, // the tag says it
		{Image: "mystery:1"},
	}
	out := ResolveOS(context.Background(), f, in, 10)
	want := []string{"debian 13", "debian 13", "alpine 3.21", "ubuntu 26.04", " ", "debian 12", " "}
	for i, w := range want {
		if got := out[i].OS + " " + out[i].OSVersion; got != w {
			t.Errorf("%s: got %q want %q", out[i].Image, got, w)
		}
	}
	if out[0].OSGuess || out[0].OSFrom != "registry" || out[5].OSFrom != "" {
		t.Fatalf("flags %+v %+v", out[0], out[5])
	}
	for _, c := range f.calls {
		if strings.Contains(c, "ghcr") || strings.Contains(c, "postgres") {
			t.Fatalf("asked %s", c)
		}
	}
}
