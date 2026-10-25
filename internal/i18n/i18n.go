// Package i18n carries every human-facing sentence DepGate produces in both
// Azerbaijani and English, so the UI can switch language without a rescan.
package i18n

import (
	"fmt"
	"os"
	"strings"
)

// T is one sentence in both languages.
type T struct {
	Az string `json:"az"`
	En string `json:"en"`
}

// F formats the same arguments into both templates.
func F(az, en string, args ...any) T {
	if len(args) == 0 {
		return T{Az: az, En: en}
	}
	return T{Az: fmt.Sprintf(az, args...), En: fmt.Sprintf(en, args...)}
}

// IsZero reports an empty sentence.
func (t T) IsZero() bool { return t.Az == "" && t.En == "" }

// In returns the sentence in lang ("az" or "en"), falling back to the other.
func (t T) In(lang string) string {
	if lang == "az" && t.Az != "" {
		return t.Az
	}
	if t.En != "" {
		return t.En
	}
	return t.Az
}

// Join renders a list in one language.
func Join(ts []T, lang, sep string) string {
	out := make([]string, len(ts))
	for i, t := range ts {
		out[i] = t.In(lang)
	}
	return strings.Join(out, sep)
}

// Lang picks the CLI language: DEPGATE_LANG, then LANG/LC_ALL starting with "az", else English.
func Lang() string {
	for _, k := range []string{"DEPGATE_LANG", "LC_ALL", "LC_MESSAGES", "LANG"} {
		v := strings.ToLower(os.Getenv(k))
		if v == "" {
			continue
		}
		if strings.HasPrefix(v, "az") {
			return "az"
		}
		return "en"
	}
	return "en"
}
