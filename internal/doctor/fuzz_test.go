package doctor

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func FuzzABIAndRevertInputsDoNotPanic(f *testing.F) {
	f.Add(
		[]byte(`[{"type":"error","name":"InvalidAuctionData","inputs":[]}]`),
		[]byte{0xdc, 0x77, 0x6d, 0xc4},
	)
	f.Add(
		[]byte(`{"abi":[{"type":"function","name":"ping","inputs":[]}]}`),
		[]byte{0x08, 0xc3, 0x79, 0xa0},
	)
	f.Add([]byte(`not-json`), []byte{})

	f.Fuzz(func(t *testing.T, abiData []byte, revertData []byte) {
		if len(abiData) > 1<<20 || len(revertData) > 1<<20 {
			t.Skip()
		}
		catalog := abiCatalog{}
		if parsed, err := parseABI(abiData); err == nil {
			catalog.entries = append(catalog.entries, namedABI{
				name: "fuzz.json",
				abi:  parsed,
			})
		}
		revert, _ := catalog.decodeRevert(revertData)
		if !strings.HasPrefix(revert.RawData, "0x") {
			t.Fatalf("raw revert data = %q", revert.RawData)
		}
	})
}

func FuzzReportSanitizationAndSerialization(f *testing.F) {
	f.Add("ordinary evidence", "ordinary explanation")
	f.Add(
		"https://alice:password@rpc.example?token=secret",
		"\x1b[31mprivate_key=0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	)
	f.Add(string([]byte{0xff, 0xfe}), "token=nested-secret")

	f.Fuzz(func(t *testing.T, evidence, explanation string) {
		if len(evidence)+len(explanation) > 1<<20 {
			t.Skip()
		}
		report := SanitizeReport(Report{
			SchemaVersion: 1,
			CollectedAt:   time.Unix(0, 0).UTC(),
			Tool: ToolEvidence{
				Name:           "Arc Doctor",
				Version:        "fuzz",
				RulesetVersion: "1.0.0",
			},
			Findings: []Finding{
				{
					Code:        "ARC-RPT-000",
					Severity:    SeverityInfo,
					Confidence:  ConfidenceCertain,
					Title:       "Fuzz report",
					Explanation: explanation,
					Evidence:    []string{evidence},
					RuleVersion: "1.0.0",
				},
			},
		})
		data, err := json.Marshal(report)
		if err != nil {
			t.Fatalf("marshal sanitized report: %v", err)
		}
		if !json.Valid(data) {
			t.Fatalf("serialized report is not valid JSON: %q", data)
		}
		var decoded Report
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("decode serialized report: %v", err)
		}
		if !decoded.Sanitized {
			t.Fatal("serialized report is not marked sanitized")
		}
	})
}
