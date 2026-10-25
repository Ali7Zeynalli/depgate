package lockfile

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// A tiny YAML reader for the subset written by pnpm (pnpm-lock.yaml) and
// yarn berry (yarn.lock): block mappings and sequences, plain / single- /
// double-quoted scalars, one-line flow collections ({a: b}, [x, y]),
// comments and "---" document separators. Scalars stay strings; mappings
// become map[string]any and sequences []any. Anchors, tags and multi-line
// block scalars are not supported (these lockfiles never use them).

type yLine struct {
	indent int
	text   string
	num    int
}

// parseYAMLDocs returns every document in src.
func parseYAMLDocs(src string) ([]any, error) {
	var docs []any
	var cur []yLine
	flush := func() error {
		if len(cur) == 0 {
			return nil
		}
		v, next, err := yParseBlock(cur, 0, cur[0].indent)
		if err != nil {
			return err
		}
		if next < len(cur) {
			return fmt.Errorf("yaml: line %d: unexpected indentation", cur[next].num)
		}
		docs = append(docs, v)
		cur = nil
		return nil
	}
	src = strings.TrimPrefix(src, string(rune(0xFEFF)))
	for i, raw := range strings.Split(src, "\n") {
		raw = strings.TrimRight(raw, "\r")
		if raw == "---" || strings.HasPrefix(raw, "--- ") || raw == "..." {
			if err := flush(); err != nil {
				return nil, err
			}
			continue
		}
		t := strings.TrimLeft(raw, " ")
		indent := len(raw) - len(t)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if strings.HasPrefix(t, "\t") {
			return nil, fmt.Errorf("yaml: line %d: tab indentation", i+1)
		}
		t = strings.TrimRight(yStripComment(t), " \t")
		if t == "" {
			continue
		}
		cur = append(cur, yLine{indent: indent, text: t, num: i + 1})
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return docs, nil
}

// yStripComment removes a trailing " # comment" that is outside quotes.
func yStripComment(s string) string {
	var q byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case q != 0:
			if c == q {
				if q == '\'' && i+1 < len(s) && s[i+1] == '\'' {
					i++
					continue
				}
				q = 0
			} else if q == '"' && c == '\\' {
				i++
			}
		case c == '\'' || c == '"':
			// only a quote at a token start opens a quoted scalar
			if i == 0 || s[i-1] == ' ' || s[i-1] == '{' || s[i-1] == '[' || s[i-1] == ',' || s[i-1] == ':' || s[i-1] == '-' {
				q = c
			}
		case c == '#' && i > 0 && (s[i-1] == ' ' || s[i-1] == '\t'):
			return s[:i]
		}
	}
	return s
}

func yIsSeqItem(t string) bool { return t == "-" || strings.HasPrefix(t, "- ") }

func yParseBlock(ls []yLine, i, indent int) (any, int, error) {
	if i >= len(ls) {
		return nil, i, nil
	}
	if yIsSeqItem(ls[i].text) {
		return yParseSeq(ls, i, indent)
	}
	return yParseMap(ls, i, indent)
}

func yParseSeq(ls []yLine, i, indent int) (any, int, error) {
	out := []any{}
	for i < len(ls) && ls[i].indent == indent && yIsSeqItem(ls[i].text) {
		rest := strings.TrimLeft(strings.TrimPrefix(ls[i].text, "-"), " ")
		if rest == "" {
			if i+1 < len(ls) && ls[i+1].indent > indent {
				v, next, err := yParseBlock(ls, i+1, ls[i+1].indent)
				if err != nil {
					return nil, 0, err
				}
				out = append(out, v)
				i = next
				continue
			}
			out = append(out, nil)
			i++
			continue
		}
		if _, _, ok := ySplitKey(rest); ok {
			// "- key: value" starts an inline mapping; its other keys sit at
			// the column of "key".
			col := indent + (len(ls[i].text) - len(rest))
			sub := make([]yLine, 0, 8)
			sub = append(sub, yLine{indent: col, text: rest, num: ls[i].num})
			j := i + 1
			for j < len(ls) && ls[j].indent > indent {
				sub = append(sub, ls[j])
				j++
			}
			v, next, err := yParseMap(sub, 0, col)
			if err != nil {
				return nil, 0, err
			}
			if next < len(sub) {
				return nil, 0, fmt.Errorf("yaml: line %d: bad indentation in sequence item", sub[next].num)
			}
			out = append(out, v)
			i = j
			continue
		}
		v, err := yScalar(rest)
		if err != nil {
			return nil, 0, fmt.Errorf("yaml: line %d: %w", ls[i].num, err)
		}
		out = append(out, v)
		i++
	}
	return out, i, nil
}

func yParseMap(ls []yLine, i, indent int) (any, int, error) {
	out := map[string]any{}
	for i < len(ls) {
		l := ls[i]
		if l.indent < indent {
			break
		}
		if l.indent > indent {
			return nil, 0, fmt.Errorf("yaml: line %d: unexpected indentation", l.num)
		}
		if yIsSeqItem(l.text) {
			break
		}
		key, rest, ok := ySplitKey(l.text)
		if !ok {
			return nil, 0, fmt.Errorf("yaml: line %d: expected \"key: value\", got %q", l.num, l.text)
		}
		i++
		switch {
		case rest != "":
			v, err := yScalar(rest)
			if err != nil {
				return nil, 0, fmt.Errorf("yaml: line %d: %w", l.num, err)
			}
			out[key] = v
		case i < len(ls) && ls[i].indent > indent:
			v, next, err := yParseBlock(ls, i, ls[i].indent)
			if err != nil {
				return nil, 0, err
			}
			out[key] = v
			i = next
		case i < len(ls) && ls[i].indent == indent && yIsSeqItem(ls[i].text):
			v, next, err := yParseSeq(ls, i, indent)
			if err != nil {
				return nil, 0, err
			}
			out[key] = v
			i = next
		default:
			out[key] = nil
		}
	}
	return out, i, nil
}

// ySplitKey splits "key: rest" (key may be quoted). ok=false when the line is
// not a mapping entry.
func ySplitKey(t string) (key, rest string, ok bool) {
	if t == "" {
		return "", "", false
	}
	if t[0] == '"' || t[0] == '\'' {
		k, n, err := yQuoted(t)
		if err != nil {
			return "", "", false
		}
		after := t[n:]
		if after == ":" {
			return k, "", true
		}
		if strings.HasPrefix(after, ": ") {
			return k, strings.TrimSpace(after[2:]), true
		}
		return "", "", false
	}
	if t[0] == '{' || t[0] == '[' {
		return "", "", false
	}
	if i := strings.Index(t, ": "); i > 0 {
		return strings.TrimSpace(t[:i]), strings.TrimSpace(t[i+2:]), true
	}
	if strings.HasSuffix(t, ":") && len(t) > 1 {
		return strings.TrimSpace(t[:len(t)-1]), "", true
	}
	return "", "", false
}

// yQuoted reads a quoted scalar at the start of s and returns it with the
// number of bytes consumed.
func yQuoted(s string) (string, int, error) {
	q := s[0]
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		c := s[i]
		if q == '\'' {
			if c == '\'' {
				if i+1 < len(s) && s[i+1] == '\'' {
					b.WriteByte('\'')
					i++
					continue
				}
				return b.String(), i + 1, nil
			}
			b.WriteByte(c)
			continue
		}
		switch c {
		case '"':
			return b.String(), i + 1, nil
		case '\\':
			if i+1 >= len(s) {
				return "", 0, fmt.Errorf("unterminated escape")
			}
			i++
			switch e := s[i]; e {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			case '0':
				b.WriteByte(0)
			case 'u', 'U', 'x':
				n := map[byte]int{'x': 2, 'u': 4, 'U': 8}[e]
				if i+1+n > len(s) {
					return "", 0, fmt.Errorf("short \\%c escape", e)
				}
				r, err := strconv.ParseUint(s[i+1:i+1+n], 16, 32)
				if err != nil {
					return "", 0, fmt.Errorf("bad \\%c escape", e)
				}
				var buf [utf8.UTFMax]byte
				b.Write(buf[:utf8.EncodeRune(buf[:], rune(r))])
				i += n
			default:
				b.WriteByte(e)
			}
		default:
			b.WriteByte(c)
		}
	}
	return "", 0, fmt.Errorf("unterminated quoted string")
}

// yScalar parses an inline value: quoted, flow collection or plain.
func yScalar(s string) (any, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	switch s[0] {
	case '"', '\'':
		v, n, err := yQuoted(s)
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(s[n:]) != "" {
			return nil, fmt.Errorf("trailing text after quoted scalar %q", s)
		}
		return v, nil
	case '{', '[':
		p := &yFlow{s: s}
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		p.ws()
		if p.i != len(p.s) {
			return nil, fmt.Errorf("trailing text after flow collection %q", s)
		}
		return v, nil
	}
	return s, nil
}

type yFlow struct {
	s string
	i int
}

func (p *yFlow) ws() {
	for p.i < len(p.s) && (p.s[p.i] == ' ' || p.s[p.i] == '\t') {
		p.i++
	}
}

func (p *yFlow) value() (any, error) {
	p.ws()
	if p.i >= len(p.s) {
		return nil, fmt.Errorf("unexpected end of flow collection")
	}
	switch c := p.s[p.i]; c {
	case '{':
		p.i++
		m := map[string]any{}
		for {
			p.ws()
			if p.i < len(p.s) && p.s[p.i] == '}' {
				p.i++
				return m, nil
			}
			k, err := p.scalar(true)
			if err != nil {
				return nil, err
			}
			p.ws()
			var v any
			if p.i < len(p.s) && p.s[p.i] == ':' {
				p.i++
				if v, err = p.value(); err != nil {
					return nil, err
				}
			}
			m[k] = v
			p.ws()
			if p.i < len(p.s) && p.s[p.i] == ',' {
				p.i++
				continue
			}
			if p.i < len(p.s) && p.s[p.i] == '}' {
				p.i++
				return m, nil
			}
			return nil, fmt.Errorf("expected , or } in %q", p.s)
		}
	case '[':
		p.i++
		l := []any{}
		for {
			p.ws()
			if p.i < len(p.s) && p.s[p.i] == ']' {
				p.i++
				return l, nil
			}
			v, err := p.value()
			if err != nil {
				return nil, err
			}
			l = append(l, v)
			p.ws()
			if p.i < len(p.s) && p.s[p.i] == ',' {
				p.i++
				continue
			}
			if p.i < len(p.s) && p.s[p.i] == ']' {
				p.i++
				return l, nil
			}
			return nil, fmt.Errorf("expected , or ] in %q", p.s)
		}
	}
	return p.scalar(false)
}

// scalar reads a quoted or plain scalar inside a flow collection. Keys end at
// ':' followed by a space or a flow indicator; values at , } or ].
func (p *yFlow) scalar(key bool) (string, error) {
	p.ws()
	if p.i < len(p.s) && (p.s[p.i] == '"' || p.s[p.i] == '\'') {
		v, n, err := yQuoted(p.s[p.i:])
		if err != nil {
			return "", err
		}
		p.i += n
		return v, nil
	}
	start := p.i
	for p.i < len(p.s) {
		c := p.s[p.i]
		if c == ',' || c == '}' || c == ']' {
			break
		}
		if key && c == ':' && (p.i+1 == len(p.s) || strings.IndexByte(" ,}]", p.s[p.i+1]) >= 0) {
			break
		}
		if !key && c == ':' && p.i+1 < len(p.s) && p.s[p.i+1] == ' ' {
			break
		}
		p.i++
	}
	return strings.TrimSpace(p.s[start:p.i]), nil
}

// small typed accessors

func yMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func yStr(v any) string {
	s, _ := v.(string)
	return s
}

func yBool(v any) bool { return yStr(v) == "true" }

// yStrMap converts a mapping of scalars to map[string]string.
func yStrMap(v any) map[string]string {
	m := yMap(v)
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, x := range m {
		out[k] = yStr(x)
	}
	return out
}
