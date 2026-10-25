package sources

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const eolAPI = "https://endoflife.date/api/"

// Cycle is one release line of a product on endoflife.date.
type Cycle struct {
	Name    string    // "22", "3.12", "bookworm" codename is in Codename
	Code    string    // codename when known (debian/ubuntu)
	EOL     time.Time // zero when not announced
	IsEOL   bool
	LTS     bool
	Latest  string // newest version in the line, e.g. "15.10"
	Release time.Time
}

// Cycles loads the release lines of an endoflife.date product (cached a day).
// Both the v1 API and the original /api/<product>.json format are understood.
func Cycles(ctx context.Context, f Fetcher, product string) ([]Cycle, error) {
	b, err := f.Do(ctx, "GET", eolAPI+"v1/products/"+product+"/", nil, nil, 24*time.Hour)
	if err == nil {
		if cs, perr := parseEOLv1(b); perr == nil {
			return cs, nil
		}
	}
	// fall back to the original API (the v1 path may be missing or renamed)
	b, err2 := f.Do(ctx, "GET", eolAPI+product+".json", nil, nil, 24*time.Hour)
	if err2 != nil {
		if err != nil {
			return nil, fmt.Errorf("endoflife.date %s: %w", product, err)
		}
		return nil, fmt.Errorf("endoflife.date %s: %w", product, err2)
	}
	return parseEOLv0(b)
}

func parseEOLv1(b []byte) ([]Cycle, error) {
	var doc struct {
		Result struct {
			Releases []struct {
				Name        string `json:"name"`
				Codename    string `json:"codename"`
				ReleaseDate string `json:"releaseDate"`
				IsLts       bool   `json:"isLts"`
				IsEol       bool   `json:"isEol"`
				EolFrom     string `json:"eolFrom"`
				Latest      *struct {
					Name string `json:"name"`
				} `json:"latest"`
			} `json:"releases"`
		} `json:"result"`
	}
	if err := json.Unmarshal(b, &doc); err != nil || len(doc.Result.Releases) == 0 {
		return nil, errors.New("not a v1 response")
	}
	var out []Cycle
	for _, r := range doc.Result.Releases {
		c := Cycle{Name: r.Name, Code: strings.ToLower(r.Codename), IsEOL: r.IsEol, LTS: r.IsLts}
		c.EOL, _ = time.Parse("2006-01-02", r.EolFrom)
		c.Release, _ = time.Parse("2006-01-02", r.ReleaseDate)
		if r.Latest != nil {
			c.Latest = r.Latest.Name
		}
		out = append(out, c)
	}
	return out, nil
}

func parseEOLv0(b []byte) ([]Cycle, error) {
	var rows []map[string]any
	if err := json.Unmarshal(b, &rows); err != nil {
		return nil, fmt.Errorf("endoflife.date: %w", err)
	}
	var out []Cycle
	for _, r := range rows {
		c := Cycle{Name: fmt.Sprint(r["cycle"]), Code: strings.ToLower(fmt.Sprint(r["codename"]))}
		if c.Code == "<nil>" {
			c.Code = ""
		}
		switch v := r["eol"].(type) {
		case bool:
			c.IsEOL = v
		case string:
			c.EOL, _ = time.Parse("2006-01-02", v)
		}
		switch v := r["lts"].(type) {
		case bool:
			c.LTS = v
		case string:
			c.LTS = true
		}
		if l, ok := r["latest"].(string); ok {
			c.Latest = l
		}
		if d, ok := r["releaseDate"].(string); ok {
			c.Release, _ = time.Parse("2006-01-02", d)
		}
		out = append(out, c)
	}
	return out, nil
}

// Ended reports whether the cycle is past its end of life at now.
func (c Cycle) Ended(now time.Time) bool { return c.IsEOL || !c.EOL.IsZero() && !now.Before(c.EOL) }
