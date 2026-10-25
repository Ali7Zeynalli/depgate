package semver

import (
	"reflect"
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		in      string
		want    Version
		wantStr string
		wantErr bool
	}{
		{in: "1.2.3", want: Version{Major: 1, Minor: 2, Patch: 3, Raw: "1.2.3"}, wantStr: "1.2.3"},
		{in: "v1.2.3", want: Version{Major: 1, Minor: 2, Patch: 3, Raw: "v1.2.3"}, wantStr: "1.2.3"},
		{in: "=1.2.3", want: Version{Major: 1, Minor: 2, Patch: 3, Raw: "=1.2.3"}, wantStr: "1.2.3"},
		{in: "=v1.2.3", want: Version{Major: 1, Minor: 2, Patch: 3, Raw: "=v1.2.3"}, wantStr: "1.2.3"},
		{in: "  1.2.3  ", want: Version{Major: 1, Minor: 2, Patch: 3, Raw: "1.2.3"}, wantStr: "1.2.3"},
		{in: "0.0.0", want: Version{Raw: "0.0.0"}, wantStr: "0.0.0"},
		{in: "1.2.3-beta.1", want: Version{Major: 1, Minor: 2, Patch: 3, Pre: []string{"beta", "1"}, Raw: "1.2.3-beta.1"}, wantStr: "1.2.3-beta.1"},
		{in: "1.2.3-0", want: Version{Major: 1, Minor: 2, Patch: 3, Pre: []string{"0"}, Raw: "1.2.3-0"}, wantStr: "1.2.3-0"},
		{in: "1.2.3-x-y.z--", want: Version{Major: 1, Minor: 2, Patch: 3, Pre: []string{"x-y", "z--"}, Raw: "1.2.3-x-y.z--"}, wantStr: "1.2.3-x-y.z--"},
		{in: "1.2.3+build.5", want: Version{Major: 1, Minor: 2, Patch: 3, Build: "build.5", Raw: "1.2.3+build.5"}, wantStr: "1.2.3"},
		{in: "1.2.3-rc.1+sha.abc", want: Version{Major: 1, Minor: 2, Patch: 3, Pre: []string{"rc", "1"}, Build: "sha.abc", Raw: "1.2.3-rc.1+sha.abc"}, wantStr: "1.2.3-rc.1"},
		{in: "1.2.3+001", want: Version{Major: 1, Minor: 2, Patch: 3, Build: "001", Raw: "1.2.3+001"}, wantStr: "1.2.3"},
		{in: "1.2.3-0a", want: Version{Major: 1, Minor: 2, Patch: 3, Pre: []string{"0a"}, Raw: "1.2.3-0a"}, wantStr: "1.2.3-0a"},
		{in: "10.20.30", want: Version{Major: 10, Minor: 20, Patch: 30, Raw: "10.20.30"}, wantStr: "10.20.30"},

		{in: "", wantErr: true},
		{in: "v", wantErr: true},
		{in: "1", wantErr: true},
		{in: "1.2", wantErr: true},
		{in: "1.2.3.4", wantErr: true},
		{in: "01.2.3", wantErr: true},
		{in: "1.02.3", wantErr: true},
		{in: "1.2.03", wantErr: true},
		{in: "1.2.3-01", wantErr: true},
		{in: "1.2.3-", wantErr: true},
		{in: "1.2.3-beta..1", wantErr: true},
		{in: "1.2.3+", wantErr: true},
		{in: "1.2.3-be$ta", wantErr: true},
		{in: "1.x.3", wantErr: true},
		{in: "a.b.c", wantErr: true},
		{in: "-1.2.3", wantErr: true},
		{in: "1.2.-3", wantErr: true},
		{in: "1.2.3 4", wantErr: true},
		{in: "vv1.2.3", wantErr: true},
		{in: "99999999999999999999.0.0", wantErr: true},
		{in: "latest", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := Parse(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Parse(%q) = %+v, want error", tt.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse(%q) error: %v", tt.in, err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Parse(%q) = %+v, want %+v", tt.in, got, tt.want)
			}
			if s := got.String(); s != tt.wantStr {
				t.Errorf("String() = %q, want %q", s, tt.wantStr)
			}
			if got.IsPrerelease() != (len(tt.want.Pre) > 0) {
				t.Errorf("IsPrerelease() = %v", got.IsPrerelease())
			}
		})
	}
}

func TestMustParsePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("MustParse did not panic on invalid input")
		}
	}()
	MustParse("not-a-version")
}

func TestPrecedenceSpecOrder(t *testing.T) {
	order := []string{
		"0.0.0-0", "0.0.0", "0.0.1",
		"1.0.0-0", "1.0.0-1", "1.0.0-2", "1.0.0-10",
		"1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta",
		"1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0",
		"1.0.1", "1.1.0", "1.10.0", "2.0.0", "10.0.0",
	}
	for i := range order {
		for j := range order {
			a, b := MustParse(order[i]), MustParse(order[j])
			want := cmpInt(i, j)
			if got := Compare(a, b); got != want {
				t.Errorf("Compare(%s, %s) = %d, want %d", order[i], order[j], got, want)
			}
			if got := Less(a, b); got != (i < j) {
				t.Errorf("Less(%s, %s) = %v, want %v", order[i], order[j], got, i < j)
			}
		}
	}
}

func TestCompareIgnoresBuild(t *testing.T) {
	tests := []struct{ a, b string }{
		{"1.0.0+a", "1.0.0+b"},
		{"1.0.0", "1.0.0+build.1"},
		{"v1.0.0-rc.1+x", "=1.0.0-rc.1"},
	}
	for _, tt := range tests {
		if c := Compare(MustParse(tt.a), MustParse(tt.b)); c != 0 {
			t.Errorf("Compare(%s, %s) = %d, want 0", tt.a, tt.b, c)
		}
	}
}

func TestCompareLargeNumericPrerelease(t *testing.T) {
	a := MustParse("1.0.0-99999999999999999998")
	b := MustParse("1.0.0-99999999999999999999")
	if Compare(a, b) != -1 || Compare(b, a) != 1 {
		t.Fatal("large numeric prerelease identifiers compared incorrectly")
	}
}

func TestDiff(t *testing.T) {
	tests := []struct{ from, to, want string }{
		{"1.2.3", "1.2.3", "none"},
		{"1.2.3", "1.2.3+build", "none"},
		{"1.2.3", "2.0.0", "major"},
		{"2.0.0", "1.9.9", "major"},
		{"1.2.3", "1.3.0", "minor"},
		{"1.2.3", "1.2.4", "patch"},
		{"1.2.3", "1.2.3-beta", "prerelease"},
		{"1.2.3-beta.1", "1.2.3-beta.2", "prerelease"},
		{"1.2.3-beta", "1.2.3", "prerelease"},
		{"1.2.3-beta", "1.3.0", "minor"},
		{"1.2.3", "2.0.0-rc.1", "major"},
		// caret semantics for 0.x
		{"0.2.3", "0.3.0", "major"},
		{"0.2.3", "0.2.4", "patch"},
		{"0.2.3", "1.0.0", "major"},
		{"0.0.3", "0.0.4", "major"},
		{"0.0.3", "0.1.0", "major"},
		{"0.0.3", "0.0.3-rc.1", "prerelease"},
		{"0.1.0-alpha", "0.1.0", "prerelease"},
	}
	for _, tt := range tests {
		if got := Diff(MustParse(tt.from), MustParse(tt.to)); got != tt.want {
			t.Errorf("Diff(%s, %s) = %q, want %q", tt.from, tt.to, got, tt.want)
		}
	}
}

func TestParseRangeErrors(t *testing.T) {
	bad := []string{
		"latest", "next", "beta", "workspace:*", "workspace:^1.2.3", "npm:other@^1",
		"file:../x", "../x", "./local", "git+https://github.com/a/b.git", "git://github.com/a/b",
		"github:user/repo", "user/repo", "link:../pkg", "https://example.com/pkg.tgz",
		"catalog:", "catalog:react18", "^", ">=", "1.2.3.4", "^01.2.3", "~1.2.3-", "1.2-beta",
		"> 1 <", "^a.b.c",
	}
	for _, s := range bad {
		if r, err := ParseRange(s); err == nil {
			t.Errorf("ParseRange(%q) = %q, want error", s, r.String())
		}
	}
}

type rangeCase struct {
	rng  string
	norm string   // expected String(); "" to skip
	in   []string // versions that must satisfy
	out  []string // versions that must not satisfy
}

func runRangeCases(t *testing.T, cases []rangeCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.rng, func(t *testing.T) {
			r, err := ParseRange(tc.rng)
			if err != nil {
				t.Fatalf("ParseRange(%q) error: %v", tc.rng, err)
			}
			if tc.norm != "" && r.String() != tc.norm {
				t.Errorf("String() = %q, want %q", r.String(), tc.norm)
			}
			for _, v := range tc.in {
				if !r.Contains(MustParse(v)) {
					t.Errorf("%q should contain %s", tc.rng, v)
				}
			}
			for _, v := range tc.out {
				if r.Contains(MustParse(v)) {
					t.Errorf("%q should not contain %s", tc.rng, v)
				}
			}
		})
	}
}

func TestRangeAnyAndExact(t *testing.T) {
	runRangeCases(t, []rangeCase{
		{rng: "", norm: "*", in: []string{"0.0.0", "1.2.3", "99.0.0"}, out: []string{"1.0.0-beta"}},
		{rng: "*", norm: "*", in: []string{"0.0.0", "1.2.3"}, out: []string{"1.2.3-rc.1"}},
		{rng: "x", norm: "*", in: []string{"3.4.5"}},
		{rng: "X", norm: "*", in: []string{"3.4.5"}},
		{rng: "  *  ", norm: "*", in: []string{"3.4.5"}},
		{rng: "1.2.3", norm: "1.2.3", in: []string{"1.2.3", "v1.2.3", "1.2.3+build"}, out: []string{"1.2.4", "1.2.2", "1.2.3-beta"}},
		{rng: "=1.2.3", norm: "1.2.3", in: []string{"1.2.3"}, out: []string{"1.2.4"}},
		{rng: "v1.2.3", norm: "1.2.3", in: []string{"1.2.3"}},
		{rng: "= 1.2.3", norm: "1.2.3", in: []string{"1.2.3"}},
		{rng: "1.2.3-beta.1", norm: "1.2.3-beta.1", in: []string{"1.2.3-beta.1"}, out: []string{"1.2.3-beta.2", "1.2.3"}},
	})
}

func TestRangeComparators(t *testing.T) {
	runRangeCases(t, []rangeCase{
		{rng: ">1.2.3", norm: ">1.2.3", in: []string{"1.2.4", "2.0.0"}, out: []string{"1.2.3", "1.0.0", "1.2.4-beta"}},
		{rng: ">=1.2.3", norm: ">=1.2.3", in: []string{"1.2.3", "5.0.0"}, out: []string{"1.2.2", "1.2.3-rc.1"}},
		{rng: "<1.2.3", norm: "<1.2.3", in: []string{"1.2.2", "0.0.0"}, out: []string{"1.2.3", "1.2.3-beta"}},
		{rng: "<=1.2.3", norm: "<=1.2.3", in: []string{"1.2.3", "0.1.0"}, out: []string{"1.2.4"}},
		{rng: ">= 1.0.0", norm: ">=1.0.0", in: []string{"1.0.0"}, out: []string{"0.9.9"}},
		{rng: ">=1.0.0 <2.0.0", norm: ">=1.0.0 <2.0.0", in: []string{"1.0.0", "1.9.9"}, out: []string{"2.0.0", "0.9.0", "2.0.0-beta", "1.5.0-beta"}},
		{rng: ">= 1.0.0   < 2.0.0", norm: ">=1.0.0 <2.0.0", in: []string{"1.5.0"}, out: []string{"2.0.0"}},
		{rng: ">=1 <2", norm: ">=1.0.0 <2.0.0-0", in: []string{"1.0.0", "1.99.99"}, out: []string{"2.0.0", "0.9.9"}},
		// partial comparators (node-semver xRange rules)
		{rng: ">1", norm: ">=2.0.0", in: []string{"2.0.0"}, out: []string{"1.9.9"}},
		{rng: ">1.2", norm: ">=1.3.0", in: []string{"1.3.0"}, out: []string{"1.2.9"}},
		{rng: "<1.2", norm: "<1.2.0-0", in: []string{"1.1.9"}, out: []string{"1.2.0", "1.2.0-beta"}},
		{rng: "<=1.2", norm: "<1.3.0-0", in: []string{"1.2.9"}, out: []string{"1.3.0"}},
		{rng: "<=1", norm: "<2.0.0-0", in: []string{"1.9.9"}, out: []string{"2.0.0"}},
		{rng: ">=1.2", norm: ">=1.2.0", in: []string{"1.2.0"}, out: []string{"1.1.9"}},
		{rng: ">=1.x", norm: ">=1.0.0", in: []string{"1.0.0"}, out: []string{"0.9.0"}},
		{rng: ">*", norm: "<0.0.0-0", out: []string{"0.0.0", "1.0.0"}},
		{rng: ">=*", norm: "*", in: []string{"0.0.0"}},
		{rng: ">=1.2.3-beta.2", in: []string{"1.2.3-beta.2", "1.2.3-beta.3", "1.2.3", "2.0.0"}, out: []string{"1.2.3-beta.1", "1.2.4-beta.3"}},
	})
}

func TestRangeHyphen(t *testing.T) {
	runRangeCases(t, []rangeCase{
		{rng: "1.2.3 - 2.3.4", norm: ">=1.2.3 <=2.3.4", in: []string{"1.2.3", "2.3.4", "2.0.0"}, out: []string{"1.2.2", "2.3.5", "2.3.4-beta"}},
		{rng: "1.2 - 2.3.4", norm: ">=1.2.0 <=2.3.4", in: []string{"1.2.0", "2.3.4"}, out: []string{"1.1.9", "2.3.5"}},
		{rng: "1.2.3 - 2.3", norm: ">=1.2.3 <2.4.0-0", in: []string{"1.2.3", "2.3.9"}, out: []string{"2.4.0", "1.2.2"}},
		{rng: "1.2.3 - 2", norm: ">=1.2.3 <3.0.0-0", in: []string{"2.9.9"}, out: []string{"3.0.0"}},
		{rng: "1 - 2", norm: ">=1.0.0 <3.0.0-0", in: []string{"1.0.0", "2.9.9"}, out: []string{"0.9.9", "3.0.0"}},
		{rng: "* - 2", norm: "<3.0.0-0", in: []string{"0.0.0", "2.5.0"}, out: []string{"3.0.0"}},
		{rng: "1.2.3 - *", norm: ">=1.2.3", in: []string{"9.9.9"}, out: []string{"1.2.2"}},
		{rng: "v1.0.0 - v2.0.0", norm: ">=1.0.0 <=2.0.0", in: []string{"1.5.0"}},
	})
}

func TestRangeXRanges(t *testing.T) {
	runRangeCases(t, []rangeCase{
		{rng: "1.x", norm: ">=1.0.0 <2.0.0-0", in: []string{"1.0.0", "1.9.9"}, out: []string{"2.0.0", "0.9.9", "1.5.0-beta"}},
		{rng: "1.X", norm: ">=1.0.0 <2.0.0-0", in: []string{"1.2.3"}},
		{rng: "1.2.x", norm: ">=1.2.0 <1.3.0-0", in: []string{"1.2.0", "1.2.99"}, out: []string{"1.3.0", "1.1.9"}},
		{rng: "1.2.*", norm: ">=1.2.0 <1.3.0-0", in: []string{"1.2.5"}, out: []string{"1.3.0"}},
		{rng: "1", norm: ">=1.0.0 <2.0.0-0", in: []string{"1.0.0", "1.99.0"}, out: []string{"2.0.0", "0.1.0"}},
		{rng: "1.2", norm: ">=1.2.0 <1.3.0-0", in: []string{"1.2.0", "1.2.9"}, out: []string{"1.3.0"}},
		{rng: "0.x", norm: ">=0.0.0 <1.0.0-0", in: []string{"0.0.0", "0.99.0"}, out: []string{"1.0.0"}},
		{rng: "1.x.x", norm: ">=1.0.0 <2.0.0-0", in: []string{"1.5.5"}},
		{rng: "=1.x", norm: ">=1.0.0 <2.0.0-0", in: []string{"1.5.5"}},
	})
}

func TestRangeTilde(t *testing.T) {
	runRangeCases(t, []rangeCase{
		{rng: "~1.2.3", norm: ">=1.2.3 <1.3.0-0", in: []string{"1.2.3", "1.2.99"}, out: []string{"1.3.0", "1.2.2", "1.2.4-beta"}},
		{rng: "~1.2", norm: ">=1.2.0 <1.3.0-0", in: []string{"1.2.0", "1.2.9"}, out: []string{"1.3.0", "1.1.0"}},
		{rng: "~1", norm: ">=1.0.0 <2.0.0-0", in: []string{"1.0.0", "1.9.9"}, out: []string{"2.0.0"}},
		{rng: "~0.2.3", norm: ">=0.2.3 <0.3.0-0", in: []string{"0.2.3", "0.2.9"}, out: []string{"0.3.0"}},
		{rng: "~0.2", norm: ">=0.2.0 <0.3.0-0", in: []string{"0.2.0"}, out: []string{"0.3.0"}},
		{rng: "~0", norm: ">=0.0.0 <1.0.0-0", in: []string{"0.9.9"}, out: []string{"1.0.0"}},
		{rng: "~1.2.3-beta.2", norm: ">=1.2.3-beta.2 <1.3.0-0", in: []string{"1.2.3-beta.2", "1.2.3-beta.4", "1.2.3", "1.2.9"}, out: []string{"1.2.4-beta.2", "1.2.3-beta.1", "1.3.0"}},
		{rng: "~>1.2.3", norm: ">=1.2.3 <1.3.0-0", in: []string{"1.2.5"}, out: []string{"1.3.0"}},
		{rng: "~ 1.2.3", norm: ">=1.2.3 <1.3.0-0", in: []string{"1.2.5"}},
		{rng: "~*", norm: "*", in: []string{"5.0.0"}},
		{rng: "~1.x", norm: ">=1.0.0 <2.0.0-0", in: []string{"1.9.0"}},
	})
}

func TestRangeCaret(t *testing.T) {
	runRangeCases(t, []rangeCase{
		{rng: "^1.2.3", norm: ">=1.2.3 <2.0.0-0", in: []string{"1.2.3", "1.9.9", "1.2.3+b"}, out: []string{"2.0.0", "1.2.2", "1.3.0-beta", "2.0.0-0"}},
		{rng: "^0.2.3", norm: ">=0.2.3 <0.3.0-0", in: []string{"0.2.3", "0.2.99"}, out: []string{"0.3.0", "0.2.2", "1.0.0"}},
		{rng: "^0.0.3", norm: ">=0.0.3 <0.0.4-0", in: []string{"0.0.3"}, out: []string{"0.0.4", "0.0.2", "0.1.0"}},
		{rng: "^1.2.3-beta.2", norm: ">=1.2.3-beta.2 <2.0.0-0", in: []string{"1.2.3-beta.2", "1.2.3-beta.4", "1.2.3", "1.9.0"}, out: []string{"1.2.4-beta.2", "1.2.3-beta.1"}},
		{rng: "^0.0.3-beta", norm: ">=0.0.3-beta <0.0.4-0", in: []string{"0.0.3-pr.2", "0.0.3"}, out: []string{"0.0.4"}},
		{rng: "^1.2.x", norm: ">=1.2.0 <2.0.0-0", in: []string{"1.2.0", "1.9.9"}, out: []string{"2.0.0", "1.1.9"}},
		{rng: "^0.0.x", norm: ">=0.0.0 <0.1.0-0", in: []string{"0.0.0", "0.0.9"}, out: []string{"0.1.0"}},
		{rng: "^0.0", norm: ">=0.0.0 <0.1.0-0", in: []string{"0.0.5"}, out: []string{"0.1.0"}},
		{rng: "^1.x", norm: ">=1.0.0 <2.0.0-0", in: []string{"1.0.0", "1.9.9"}, out: []string{"2.0.0", "0.9.0"}},
		{rng: "^0.x", norm: ">=0.0.0 <1.0.0-0", in: []string{"0.0.0", "0.9.9"}, out: []string{"1.0.0"}},
		{rng: "^1", norm: ">=1.0.0 <2.0.0-0", in: []string{"1.0.0"}, out: []string{"2.0.0"}},
		{rng: "^0.1", norm: ">=0.1.0 <0.2.0-0", in: []string{"0.1.9"}, out: []string{"0.2.0"}},
		{rng: "^ 1.2.3", norm: ">=1.2.3 <2.0.0-0", in: []string{"1.5.0"}, out: []string{"2.0.0"}},
		{rng: "^v1.2.3", norm: ">=1.2.3 <2.0.0-0", in: []string{"1.5.0"}},
		{rng: "^*", norm: "*", in: []string{"9.0.0"}},
	})
}

func TestRangeUnionAndAnd(t *testing.T) {
	runRangeCases(t, []rangeCase{
		{rng: "1.2.7 || >=1.2.9 <2.0.0", norm: "1.2.7 || >=1.2.9 <2.0.0", in: []string{"1.2.7", "1.2.9", "1.4.6"}, out: []string{"1.2.8", "2.0.0"}},
		{rng: "^1.0.0 || ^2.0.0", norm: ">=1.0.0 <2.0.0-0 || >=2.0.0 <3.0.0-0", in: []string{"1.0.0", "2.5.0"}, out: []string{"3.0.0", "0.9.0"}},
		{rng: "1.x||>=2.5", norm: ">=1.0.0 <2.0.0-0 || >=2.5.0", in: []string{"1.0.0", "2.5.0", "3.0.0"}, out: []string{"2.0.0", "2.4.9"}},
		{rng: "<1.0.0 || >=2.0.0", in: []string{"0.5.0", "2.0.0"}, out: []string{"1.5.0"}},
		{rng: "* || 1.0.0", in: []string{"5.0.0"}},
		{rng: ">=1.2.3 <1.2.3", out: []string{"1.2.3"}},
		{rng: "^1.2.3 >=1.5.0", in: []string{"1.5.0"}, out: []string{"1.4.0", "2.0.0"}},
		{rng: "~1.2.3 1.2.x", in: []string{"1.2.5"}, out: []string{"1.3.0"}},
		{rng: "* >=1.0.0", norm: ">=1.0.0", in: []string{"1.0.0"}, out: []string{"0.1.0"}},
	})
}

func TestPrereleaseExclusion(t *testing.T) {
	tests := []struct {
		rng, v string
		want   bool
	}{
		{">1.2.3-alpha.3", "1.2.3-alpha.7", true},
		{">1.2.3-alpha.3", "3.4.5-alpha.9", false},
		{">1.2.3-alpha.3", "3.4.5", true},
		{">1.2.3-alpha.3", "1.2.3-alpha.3", false},
		{"^1.2.3", "1.5.0-beta", false},
		{"^1.2.3-rc.1", "1.2.3-rc.2", true},
		{"^1.2.3-rc.1", "1.2.4-rc.1", false},
		{"*", "1.0.0-0", false},
		{">=0.0.0", "1.0.0-beta", false},
		{"<2.0.0", "2.0.0-beta", false},
		{"<2.0.0-0", "1.9.9-beta", false},
		{"1.0.0-beta || 2.0.0-beta", "2.0.0-beta", true},
		{">=1.0.0-0 <2.0.0", "1.0.0-alpha", true},
		{">=1.0.0-0 <2.0.0", "1.1.0-alpha", false},
		{"1.2.3-beta - 1.3.0-beta", "1.3.0-alpha", true},
		{"1.2.3-beta - 1.3.0-beta", "1.2.5-alpha", false},
	}
	for _, tt := range tests {
		r, err := ParseRange(tt.rng)
		if err != nil {
			t.Fatalf("ParseRange(%q): %v", tt.rng, err)
		}
		if got := r.Contains(MustParse(tt.v)); got != tt.want {
			t.Errorf("%q.Contains(%s) = %v, want %v", tt.rng, tt.v, got, tt.want)
		}
	}
}

func TestMinVersion(t *testing.T) {
	tests := []struct {
		rng  string
		want string // "" means no minimum
	}{
		{"*", "0.0.0"},
		{"", "0.0.0"},
		{">=1.0.0", "1.0.0"},
		{"^1.2.3", "1.2.3"},
		{"~1.2", "1.2.0"},
		{">1.0.0", "1.0.1"},
		{">1.0.0-beta", "1.0.0-beta.0"},
		{">=1.0.0-0", "1.0.0-0"},
		{"<2", "0.0.0"},
		{"<0.0.1", "0.0.0"},
		{"<=1.2.3", "0.0.0"},
		{">=0.0.0-0", "0.0.0"},
		{"<0.0.0", ""},
		{"1.x||>=2.5", "1.0.0"},
		{">=2.5 || 1.x", "1.0.0"},
		{"1.2.3", "1.2.3"},
		{"1.2.3-rc.1", "1.2.3-rc.1"},
		{"^0.0.3", "0.0.3"},
		{"1.2 - 2.3.4", "1.2.0"},
		{">1", "2.0.0"},
		{">1.2", "1.3.0"},
		{">=1.0.0 >=1.5.0 <2", "1.5.0"},
		{">1.0.0 <1.0.1", ""},
		{">*", ""},
		{">=2.0.0 <1.0.0", ""},
	}
	for _, tt := range tests {
		r, err := ParseRange(tt.rng)
		if err != nil {
			t.Fatalf("ParseRange(%q): %v", tt.rng, err)
		}
		got, ok := MinVersion(r)
		if tt.want == "" {
			if ok {
				t.Errorf("MinVersion(%q) = %s, want none", tt.rng, got)
			}
			continue
		}
		if !ok || got.String() != tt.want {
			t.Errorf("MinVersion(%q) = %s, %v; want %s", tt.rng, got, ok, tt.want)
		}
	}
}

func TestMaxMinSatisfying(t *testing.T) {
	var vs []Version
	for _, s := range []string{"1.2.3", "1.2.4", "1.3.0-beta", "1.3.0", "2.0.0-rc.1", "2.0.0", "0.9.0", "1.2.4-beta"} {
		vs = append(vs, MustParse(s))
	}
	tests := []struct {
		rng      string
		max, min string // "" means none
	}{
		{"^1.2.3", "1.3.0", "1.2.3"},
		{"~1.2.3", "1.2.4", "1.2.3"},
		{"*", "2.0.0", "0.9.0"},
		{">=2.0.0-rc.1", "2.0.0", "2.0.0-rc.1"},
		{"^3.0.0", "", ""},
		{"<1.0.0", "0.9.0", "0.9.0"},
		{"1.2.4-beta || 1.2.3", "1.2.4-beta", "1.2.3"},
	}
	for _, tt := range tests {
		r, err := ParseRange(tt.rng)
		if err != nil {
			t.Fatalf("ParseRange(%q): %v", tt.rng, err)
		}
		check := func(name string, got Version, ok bool, want string) {
			if want == "" {
				if ok {
					t.Errorf("%s(%q) = %s, want none", name, tt.rng, got)
				}
				return
			}
			if !ok || got.String() != want {
				t.Errorf("%s(%q) = %s, %v; want %s", name, tt.rng, got, ok, want)
			}
		}
		gMax, okMax := MaxSatisfying(vs, r)
		check("MaxSatisfying", gMax, okMax, tt.max)
		gMin, okMin := MinSatisfying(vs, r)
		check("MinSatisfying", gMin, okMin, tt.min)
	}
	if _, ok := MaxSatisfying(nil, Range{}); ok {
		t.Error("MaxSatisfying(nil) should report none")
	}
}
