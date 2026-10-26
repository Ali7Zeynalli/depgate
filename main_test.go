package main

import (
	"testing"

	"github.com/Ali7Zeynalli/depgate/internal/report"
)

func TestExitCodeSkipsAcceptedRisks(t *testing.T) {
	c := config{ci: true, failOn: "high"}
	rep := &report.Report{Projects: []report.Project{{Findings: []report.Finding{
		{Kind: "vuln", Severity: "critical", Group: report.GroupAccepted, Accepted: &report.Accepted{Reason: "x"}},
		{Kind: "vuln", Severity: "moderate", Group: report.GroupNowEasy},
	}}}}
	if exitCode(rep, c) != 0 {
		t.Fatal("an accepted risk must not fail CI")
	}
	rep.Projects[0].Findings = append(rep.Projects[0].Findings, report.Finding{Kind: "vuln", Severity: "high", Group: report.GroupNowEasy})
	if exitCode(rep, c) != 1 {
		t.Fatal("a high vulnerability must fail CI")
	}
	if v := version; v == "" {
		t.Fatal("version not set from the VERSION file")
	}
}
