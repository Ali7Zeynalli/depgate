package explain

import "testing"

func TestWeaknesses(t *testing.T) {
	ws := Weaknesses([]string{"CWE-9999", "cwe-1321", "CWE-1321", "NVD-CWE-Other", ""})
	if len(ws) != 2 {
		t.Fatalf("got %+v", ws)
	}
	if ws[0].ID != "CWE-1321" || ws[0].Name.En != "Prototype pollution" || ws[0].What.Az == "" || ws[0].Risk.En == "" {
		t.Errorf("known CWE first and explained: %+v", ws[0])
	}
	if ws[1].ID != "CWE-9999" || ws[1].Name.En != "" || ws[1].URL != "https://cwe.mitre.org/data/definitions/9999.html" {
		t.Errorf("unknown CWE keeps id and link: %+v", ws[1])
	}
	for id, e := range cwes {
		for _, s := range []string{e.name.Az, e.name.En, e.what.Az, e.what.En, e.risk.Az, e.risk.En} {
			if s == "" {
				t.Errorf("%s has an empty text", id)
			}
		}
	}
}
