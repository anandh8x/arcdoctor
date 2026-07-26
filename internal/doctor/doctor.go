package doctor

import (
	"context"
	"fmt"
	"time"
)

const ArcTestnetChainID uint64 = 5_042_002

type RequestKind string

const NetworkCheck RequestKind = "network"

type Request struct {
	Kind RequestKind
}

type NetworkSnapshot struct {
	ChainID        uint64
	BlockNumber    uint64
	BlockTimestamp time.Time
	Latency        time.Duration
}

type NetworkEvidence struct {
	ExpectedChainID     uint64        `json:"expectedChainId"`
	ObservedChainID     uint64        `json:"observedChainId"`
	BlockNumber         uint64        `json:"blockNumber"`
	BlockTimestamp      time.Time     `json:"blockTimestamp"`
	Latency             time.Duration `json:"-"`
	LatencyMilliseconds float64       `json:"latencyMs"`
}

type Severity string

const (
	SeverityError   Severity = "error"
	SeverityWarning Severity = "warning"
	SeverityInfo    Severity = "info"
)

type Confidence string

const (
	ConfidenceCertain  Confidence = "certain"
	ConfidenceLikely   Confidence = "likely"
	ConfidencePossible Confidence = "possible"
)

type Finding struct {
	Code             string     `json:"code"`
	Severity         Severity   `json:"severity"`
	Confidence       Confidence `json:"confidence"`
	Title            string     `json:"title"`
	Explanation      string     `json:"explanation"`
	Evidence         []string   `json:"evidence"`
	SuggestedActions []string   `json:"suggestedActions,omitempty"`
}

type Report struct {
	Network  NetworkEvidence `json:"network"`
	Findings []Finding       `json:"findings"`
}

func (r Report) HasErrors() bool {
	for _, finding := range r.Findings {
		if finding.Severity == SeverityError {
			return true
		}
	}
	return false
}

type NetworkProbe interface {
	NetworkSnapshot(context.Context) (NetworkSnapshot, error)
}

type Doctor struct {
	network NetworkProbe
}

func New(network NetworkProbe) *Doctor {
	return &Doctor{network: network}
}

func (d *Doctor) Diagnose(ctx context.Context, request Request) (Report, error) {
	if request.Kind != NetworkCheck {
		return Report{}, fmt.Errorf("unsupported diagnostic request kind %q", request.Kind)
	}

	snapshot, err := d.network.NetworkSnapshot(ctx)
	if err != nil {
		return Report{}, fmt.Errorf("collect network evidence: %w", err)
	}

	finding := Finding{
		Code:        "ARC-NET-000",
		Severity:    SeverityInfo,
		Confidence:  ConfidenceCertain,
		Title:       "Arc Testnet connection confirmed",
		Explanation: "The RPC endpoint reported the expected Arc Testnet chain ID.",
		Evidence: []string{
			fmt.Sprintf("Expected chain ID: %d", ArcTestnetChainID),
			fmt.Sprintf("Observed chain ID: %d", snapshot.ChainID),
		},
	}

	if snapshot.ChainID != ArcTestnetChainID {
		finding = Finding{
			Code:        "ARC-NET-002",
			Severity:    SeverityError,
			Confidence:  ConfidenceCertain,
			Title:       "RPC is connected to the wrong network",
			Explanation: "The RPC endpoint reported a chain ID that does not match Arc Testnet.",
			Evidence: []string{
				fmt.Sprintf("Expected chain ID: %d", ArcTestnetChainID),
				fmt.Sprintf("Observed chain ID: %d", snapshot.ChainID),
			},
			SuggestedActions: []string{
				"Verify that the RPC URL points to Arc Testnet.",
				"Check the network configuration used by the application.",
			},
		}
	}

	report := Report{
		Network: NetworkEvidence{
			ExpectedChainID:     ArcTestnetChainID,
			ObservedChainID:     snapshot.ChainID,
			BlockNumber:         snapshot.BlockNumber,
			BlockTimestamp:      snapshot.BlockTimestamp,
			Latency:             snapshot.Latency,
			LatencyMilliseconds: float64(snapshot.Latency) / float64(time.Millisecond),
		},
		Findings: []Finding{finding},
	}

	return report, nil
}
