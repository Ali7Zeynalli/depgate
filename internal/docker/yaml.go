package docker

import (
	"fmt"
	"regexp"
	"strings"
)

// A deliberately small YAML reader: enough of the language for docker-compose
// files (block maps and lists, flow collections, quoted scalars, comments).
// Anchors are dropped, aliases become yAlias nodes, block scalars are skipped.
// Any parse problem makes parseYAML return an error; it never panics outward.

type yKind int

const (
	yNull yKind = iota
	yScalar
	yMap
	ySeq
	yAlias
)

type yNode struct {
	Kind  yKind
	Value string // scalar text (unquoted)
	Line  int    // 1-based line of the node
	Keys  []yKey // yMap entries, in order
	Items []*yNode
}

type yKey struct {
	Name string
	Line int
	Val  *yNode
}

// get returns the value of key k in a map node, or nil.
func (n *yNode) get(k string) *yNode {
	if n == nil || n.Kind != yMap {
		return nil
	}
	for _, e := range n.Keys {
		if e.Name == k {
			return e.Val
		}
	}
	return nil
}

// str is the scalar text of n ("" for anything else).
func (n *yNode) str() string {
	if n == nil || n.Kind != yScalar {
		return ""
	}
	return n.Value
}

type yLine struct {
	indent int
	text   string
	no     int
}

type yParser struct {
	lines []yLine
	i     int
}

var blockScalarRe = regexp.MustCompile(`(^|[:\-]\s+|^-)\s*[|>][+\-0-9]*$`)

// parseYAML parses the first document of src.
func parseYAML(src string) (root *yNode, err error) {
	defer func() {
		if r := recover(); r != nil {
			root, err = nil, fmt.Errorf("yaml: %v", r)
		}
	}()
	p := &yParser{lines: splitYAML(src)}
	if len(p.lines) == 0 {
		return &yNode{Kind: yNull}, nil
	}
	root = p.block(p.lines[0].indent)
	if p.i < len(p.lines) {
		panic(fmt.Sprintf("line %d: unexpected content", p.lines[p.i].no))
	}
	return root, nil
}

// splitYAML turns src into significant lines: comments and blanks removed,
// block-scalar bodies skipped, stopping at a second document marker.
func splitYAML(src string) []yLine {
	var out []yLine
	raw := strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n")
	skipAbove := -1 // while >= 0, lines indented deeper than this are block-scalar body
	for i, s := range raw {
		ind := 0
		for ind < len(s) && (s[ind] == ' ' || s[ind] == '\t') {
			ind++
		}
		body := strings.TrimRight(s[ind:], " \t")
		if skipAbove >= 0 {
			if body == "" || ind > skipAbove {
				continue
			}
			skipAbove = -1
		}
		if ind == 0 && (body == "---" || strings.HasPrefix(body, "--- ") || body == "...") {
			if len(out) > 0 {
				break
			}
			continue
		}
		if ind == 0 && strings.HasPrefix(body, "%") {
			continue
		}
		text := strings.TrimRight(stripComment(body), " \t")
		if text == "" {
			continue
		}
		if blockScalarRe.MatchString(text) {
			skipAbove = ind
		}
		out = append(out, yLine{indent: ind, text: text, no: i + 1})
	}
	return out
}

// stripComment removes a trailing "# ..." that is outside quotes.
func stripComment(s string) string {
	var q byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case q == '"':
			if c == '\\' {
				i++
			} else if c == '"' {
				q = 0
			}
		case q == '\'':
			if c == '\'' && i+1 < len(s) && s[i+1] == '\'' {
				i++
			} else if c == '\'' {
				q = 0
			}
		case c == '"' || c == '\'':
			if i == 0 || strings.IndexByte(" \t[{,:-?", s[i-1]) >= 0 {
				q = c
			}
		case c == '#':
			if i == 0 || s[i-1] == ' ' || s[i-1] == '\t' {
				return s[:i]
			}
		}
	}
	return s
}

func isSeqItem(t string) bool {
	return t == "-" || strings.HasPrefix(t, "- ") || strings.HasPrefix(t, "-\t")
}

func (p *yParser) block(ind int) *yNode {
	l := p.lines[p.i]
	if isSeqItem(l.text) {
		return p.seq(l.indent)
	}
	if _, _, ok := splitKey(l.text); ok {
		return p.mapping(l.indent)
	}
	p.i++
	return p.value(l.text, l.no, ind)
}

func (p *yParser) seq(ind int) *yNode {
	n := &yNode{Kind: ySeq, Line: p.lines[p.i].no}
	for p.i < len(p.lines) {
		l := p.lines[p.i]
		if l.indent < ind || (l.indent == ind && !isSeqItem(l.text)) {
			break
		}
		if l.indent > ind {
			panic(fmt.Sprintf("line %d: bad indentation", l.no))
		}
		rest := strings.TrimLeft(l.text[1:], " \t")
		if rest == "" {
			p.i++
			if p.i < len(p.lines) && p.lines[p.i].indent > ind {
				n.Items = append(n.Items, p.block(p.lines[p.i].indent))
			} else {
				n.Items = append(n.Items, &yNode{Kind: yNull, Line: l.no})
			}
			continue
		}
		off := len(l.text) - len(rest)
		p.lines[p.i] = yLine{indent: ind + off, text: rest, no: l.no}
		n.Items = append(n.Items, p.block(ind+off))
	}
	return n
}

func (p *yParser) mapping(ind int) *yNode {
	n := &yNode{Kind: yMap, Line: p.lines[p.i].no}
	for p.i < len(p.lines) {
		l := p.lines[p.i]
		if l.indent < ind || (l.indent == ind && isSeqItem(l.text)) {
			break
		}
		if l.indent > ind {
			panic(fmt.Sprintf("line %d: bad indentation", l.no))
		}
		k, v, ok := splitKey(l.text)
		if !ok {
			panic(fmt.Sprintf("line %d: expected a key", l.no))
		}
		p.i++
		e := yKey{Name: unquote(k), Line: l.no}
		v = stripProps(v)
		if v == "" {
			if p.i < len(p.lines) {
				nx := p.lines[p.i]
				if nx.indent > ind {
					e.Val = p.block(nx.indent)
				} else if nx.indent == ind && isSeqItem(nx.text) {
					e.Val = p.seq(ind)
				}
			}
			if e.Val == nil {
				e.Val = &yNode{Kind: yNull, Line: l.no}
			}
		} else {
			e.Val = p.value(v, l.no, ind)
		}
		if e.Name != "<<" {
			n.Keys = append(n.Keys, e)
		}
	}
	return n
}

// value parses an inline value; flow collections and quoted strings may
// continue on following lines, plain scalars may fold deeper-indented lines.
func (p *yParser) value(v string, line, ind int) *yNode {
	v = stripProps(v)
	switch {
	case v == "":
		return &yNode{Kind: yNull, Line: line}
	case v[0] == '*':
		return &yNode{Kind: yAlias, Value: v, Line: line}
	case v[0] == '|' || v[0] == '>':
		return &yNode{Kind: yScalar, Line: line}
	case v[0] == '[' || v[0] == '{':
		for !balanced(v) && p.i < len(p.lines) {
			v += " " + p.lines[p.i].text
			p.i++
		}
		f := &flow{s: v, line: line}
		n := f.node(false)
		f.ws()
		if f.pos != len(f.s) {
			panic(fmt.Sprintf("line %d: trailing flow content", line))
		}
		return n
	case v[0] == '"' || v[0] == '\'':
		for !quoteClosed(v) && p.i < len(p.lines) {
			v += " " + p.lines[p.i].text
			p.i++
		}
		if !quoteClosed(v) {
			panic(fmt.Sprintf("line %d: unterminated quote", line))
		}
	default:
		for p.i < len(p.lines) && p.lines[p.i].indent > ind {
			v += " " + p.lines[p.i].text
			p.i++
		}
	}
	return &yNode{Kind: yScalar, Value: unquote(v), Line: line}
}

// stripProps drops leading anchors (&x) and tags (!t).
func stripProps(v string) string {
	v = strings.TrimSpace(v)
	for v != "" && (v[0] == '&' || v[0] == '!') {
		i := strings.IndexAny(v, " \t")
		if i < 0 {
			return ""
		}
		v = strings.TrimSpace(v[i:])
	}
	return v
}

// splitKey splits "key: value" at the first ':' outside quotes and brackets
// that is followed by whitespace or the end of the line.
func splitKey(t string) (key, val string, ok bool) {
	i := 0
	if t != "" && (t[0] == '"' || t[0] == '\'') {
		end := closingQuote(t)
		if end < 0 {
			return "", "", false
		}
		i = end + 1
		rest := strings.TrimLeft(t[i:], " \t")
		if !strings.HasPrefix(rest, ":") {
			return "", "", false
		}
		after := rest[1:]
		if after != "" && after[0] != ' ' && after[0] != '\t' {
			return "", "", false
		}
		return t[:i], strings.TrimSpace(after), true
	}
	if t != "" && strings.IndexByte("[{&*!|>", t[0]) >= 0 && !strings.HasPrefix(t, "<<") {
		return "", "", false
	}
	for ; i < len(t); i++ {
		if t[i] == ':' && (i+1 == len(t) || t[i+1] == ' ' || t[i+1] == '\t') {
			return strings.TrimSpace(t[:i]), strings.TrimSpace(t[i+1:]), i > 0
		}
	}
	return "", "", false
}

// closingQuote returns the index of the quote closing the one at t[0], or -1.
func closingQuote(t string) int {
	q := t[0]
	for i := 1; i < len(t); i++ {
		switch {
		case q == '"' && t[i] == '\\':
			i++
		case t[i] == q:
			if q == '\'' && i+1 < len(t) && t[i+1] == '\'' {
				i++
				continue
			}
			return i
		}
	}
	return -1
}

func quoteClosed(v string) bool { return closingQuote(v) >= 0 }

func balanced(s string) bool {
	depth := 0
	var q byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case q == '"' && c == '\\':
			i++
		case q != 0:
			if c == q {
				q = 0
			}
		case c == '"' || c == '\'':
			q = c
		case c == '[' || c == '{':
			depth++
		case c == ']' || c == '}':
			depth--
		}
	}
	return depth <= 0
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) < 2 {
		return s
	}
	switch s[0] {
	case '\'':
		if end := closingQuote(s); end > 0 {
			return strings.ReplaceAll(s[1:end], "''", "'")
		}
	case '"':
		end := closingQuote(s)
		if end <= 0 {
			return s
		}
		var b strings.Builder
		in := s[1:end]
		for i := 0; i < len(in); i++ {
			if in[i] == '\\' && i+1 < len(in) {
				i++
				switch in[i] {
				case 'n':
					b.WriteByte('\n')
				case 't':
					b.WriteByte('\t')
				default:
					b.WriteByte(in[i])
				}
				continue
			}
			b.WriteByte(in[i])
		}
		return b.String()
	}
	return s
}

// flow parses [a, b] and {a: b} collections.
type flow struct {
	s    string
	pos  int
	line int
}

func (f *flow) ws() {
	for f.pos < len(f.s) && (f.s[f.pos] == ' ' || f.s[f.pos] == '\t') {
		f.pos++
	}
}

func (f *flow) fail(msg string) {
	panic(fmt.Sprintf("line %d: %s", f.line, msg))
}

func (f *flow) node(isKey bool) *yNode {
	f.ws()
	if f.pos >= len(f.s) {
		f.fail("unexpected end of flow")
	}
	switch c := f.s[f.pos]; c {
	case '[':
		f.pos++
		n := &yNode{Kind: ySeq, Line: f.line}
		for {
			f.ws()
			if f.pos < len(f.s) && f.s[f.pos] == ']' {
				f.pos++
				return n
			}
			n.Items = append(n.Items, f.node(false))
			f.ws()
			if f.pos < len(f.s) && f.s[f.pos] == ',' {
				f.pos++
				continue
			}
			if f.pos < len(f.s) && f.s[f.pos] == ']' {
				f.pos++
				return n
			}
			f.fail("expected , or ]")
		}
	case '{':
		f.pos++
		n := &yNode{Kind: yMap, Line: f.line}
		for {
			f.ws()
			if f.pos < len(f.s) && f.s[f.pos] == '}' {
				f.pos++
				return n
			}
			k := f.node(true)
			f.ws()
			e := yKey{Name: k.Value, Line: f.line, Val: &yNode{Kind: yNull, Line: f.line}}
			if f.pos < len(f.s) && f.s[f.pos] == ':' {
				f.pos++
				f.ws()
				if f.pos < len(f.s) && f.s[f.pos] != ',' && f.s[f.pos] != '}' {
					e.Val = f.node(false)
				}
			}
			n.Keys = append(n.Keys, e)
			f.ws()
			if f.pos < len(f.s) && f.s[f.pos] == ',' {
				f.pos++
				continue
			}
			if f.pos < len(f.s) && f.s[f.pos] == '}' {
				f.pos++
				return n
			}
			f.fail("expected , or }")
		}
	case '"', '\'':
		end := closingQuote(f.s[f.pos:])
		if end < 0 {
			f.fail("unterminated quote")
		}
		v := unquote(f.s[f.pos : f.pos+end+1])
		f.pos += end + 1
		return &yNode{Kind: yScalar, Value: v, Line: f.line}
	default:
		start := f.pos
		for f.pos < len(f.s) {
			c := f.s[f.pos]
			if c == ',' || c == ']' || c == '}' || (isKey && c == ':') {
				break
			}
			f.pos++
		}
		v := strings.TrimSpace(f.s[start:f.pos])
		if strings.HasPrefix(v, "*") {
			return &yNode{Kind: yAlias, Value: v, Line: f.line}
		}
		return &yNode{Kind: yScalar, Value: stripProps(v), Line: f.line}
	}
}
