package doctor_test

import (
	"context"
	"fmt"
	"math/big"
	"testing"

	"github.com/anandh8x/arcdoctor/internal/doctor"
)

func TestDiagnoseDeploymentValidatesKnownArcContracts(t *testing.T) {
	t.Parallel()

	const (
		invoiceAddress = "0xCe084c9358FBC5200415012885c2F0F0906d400C"
		auctionAddress = "0x0C83623d0abFca5e7ad6E6179bB45A3E70C6C9DA"
		invoiceTx      = "0xaadb9724bd8211ac78cc818465b0f7d144626e4f8dfd99f908e25f2e8609d1c8"
		auctionTx      = "0x4ac202bc8b1f25e3a4b466051b87a946ebd2ec2efe7782df45e9e3301a566211"
	)
	manifest := []byte(fmt.Sprintf(`{
		"schemaVersion": 1,
		"network": "Arc Testnet",
		"chainId": 5042002,
		"contracts": {
			"InvoiceRegistry": {
				"address": %q,
				"transactionHash": %q
			},
			"SealedBidAuction": {
				"address": %q,
				"transactionHash": %q
			}
		}
	}`, invoiceAddress, invoiceTx, auctionAddress, auctionTx))

	address := addressProbeFunc(func(
		_ context.Context,
		gotAddress string,
	) (doctor.AddressSnapshot, error) {
		switch gotAddress {
		case invoiceAddress:
			return doctor.AddressSnapshot{
				BalanceBaseUnits: big.NewInt(0),
				Nonce:            1,
				Code:             []byte{0x60, 0x01},
			}, nil
		case auctionAddress:
			return doctor.AddressSnapshot{
				BalanceBaseUnits: big.NewInt(0),
				Nonce:            1,
				Code:             []byte{0x60, 0x02},
			}, nil
		default:
			return doctor.AddressSnapshot{}, fmt.Errorf("unexpected address %s", gotAddress)
		}
	})
	transaction := transactionProbeFunc(func(
		_ context.Context,
		hash string,
	) (doctor.TransactionSnapshot, error) {
		to := invoiceAddress
		if hash == auctionTx {
			to = auctionAddress
		}
		return doctor.TransactionSnapshot{
			Found:          true,
			To:             "",
			ValueBaseUnits: big.NewInt(0),
			Receipt: &doctor.TransactionReceiptSnapshot{
				Status:          1,
				ContractAddress: to,
			},
		}, nil
	})

	report, err := doctor.New(
		arcNetworkProbe(),
		doctor.WithAddressProbe(address),
		doctor.WithTransactionProbe(transaction),
	).Diagnose(context.Background(), doctor.Request{
		Kind: doctor.DeploymentCheck,
		Deployment: &doctor.DeploymentInput{
			Name: "arc-testnet.json",
			Data: manifest,
		},
	})
	if err != nil {
		t.Fatalf("Diagnose() error = %v", err)
	}
	if report.HasErrors() {
		t.Fatalf("HasErrors() = true, findings = %#v", report.Findings)
	}
	if report.Deployment == nil {
		t.Fatal("Deployment evidence is nil")
	}
	if len(report.Deployment.Contracts) != 2 {
		t.Fatalf("len(Contracts) = %d, want 2", len(report.Deployment.Contracts))
	}
	if report.Deployment.Contracts[0].Name != "InvoiceRegistry" {
		t.Errorf(
			"Contracts[0].Name = %q, want deterministic alphabetical ordering",
			report.Deployment.Contracts[0].Name,
		)
	}
	if !hasFinding(report, "ARC-DEP-000") {
		t.Fatalf("Findings = %#v, want ARC-DEP-000", report.Findings)
	}
}

func TestDiagnoseDeploymentRejectsWrongChainAndMissingBytecode(t *testing.T) {
	t.Parallel()

	const localAddress = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
	manifest := []byte(`{
		"schemaVersion": 1,
		"network": "Arc Testnet",
		"chainId": 31337,
		"contracts": {
			"LocalContract": {
				"address": "0x5FbDB2315678afecb367f032d93F642f64180aa3"
			}
		}
	}`)
	address := addressProbeFunc(func(
		_ context.Context,
		gotAddress string,
	) (doctor.AddressSnapshot, error) {
		if gotAddress != localAddress {
			t.Errorf("AddressSnapshot() address = %q, want %q", gotAddress, localAddress)
		}
		return doctor.AddressSnapshot{BalanceBaseUnits: big.NewInt(0)}, nil
	})

	report, err := doctor.New(
		arcNetworkProbe(),
		doctor.WithAddressProbe(address),
	).Diagnose(context.Background(), doctor.Request{
		Kind: doctor.DeploymentCheck,
		Deployment: &doctor.DeploymentInput{
			Name: "local.json",
			Data: manifest,
		},
	})
	if err != nil {
		t.Fatalf("Diagnose() error = %v", err)
	}
	for _, code := range []string{"ARC-DEP-003", "ARC-DEP-006", "ARC-DEP-016"} {
		if !hasFinding(report, code) {
			t.Errorf("Findings = %#v, want %s", report.Findings, code)
		}
	}
	if !report.HasErrors() {
		t.Fatal("HasErrors() = false, want invalid deployment")
	}
}

func TestDiagnoseDeploymentComparesArtifactRuntimeBytecode(t *testing.T) {
	t.Parallel()

	const addressValue = "0x1111111111111111111111111111111111111111"
	manifest := []byte(`{
		"schemaVersion": 1,
		"network": "Arc Testnet",
		"chainId": 5042002,
		"contracts": {
			"Counter": {
				"address": "0x1111111111111111111111111111111111111111",
				"artifact": "out/Counter.json"
			}
		}
	}`)
	runtimeCode := []byte{0x60, 0x01, 0x60, 0x02}
	address := addressProbeFunc(func(
		context.Context,
		string,
	) (doctor.AddressSnapshot, error) {
		return doctor.AddressSnapshot{
			BalanceBaseUnits: big.NewInt(0),
			Code:             runtimeCode,
		}, nil
	})
	loader := func(path string) ([]byte, error) {
		if path != "/project/out/Counter.json" {
			return nil, fmt.Errorf("unexpected artifact path %q", path)
		}
		return []byte(`{
			"deployedBytecode": {
				"object": "0x60016002"
			}
		}`), nil
	}

	report, err := doctor.New(
		arcNetworkProbe(),
		doctor.WithAddressProbe(address),
		doctor.WithArtifactLoader(loader),
	).Diagnose(context.Background(), doctor.Request{
		Kind: doctor.DeploymentCheck,
		Deployment: &doctor.DeploymentInput{
			Name:    "deployment.json",
			BaseDir: "/project",
			Data:    manifest,
		},
	})
	if err != nil {
		t.Fatalf("Diagnose() error = %v", err)
	}
	if report.HasErrors() {
		t.Fatalf("HasErrors() = true, findings = %#v", report.Findings)
	}
	if !hasFinding(report, "ARC-DEP-013") {
		t.Fatalf("Findings = %#v, want ARC-DEP-013", report.Findings)
	}
	if report.Deployment == nil ||
		len(report.Deployment.Contracts) != 1 ||
		report.Deployment.Contracts[0].ArtifactComparison !=
			doctor.ArtifactComparisonExact {
		t.Fatalf("Deployment = %#v, want exact artifact comparison", report.Deployment)
	}
	if report.Deployment.Contracts[0].Address != addressValue {
		t.Errorf("contract address = %q, want %q", report.Deployment.Contracts[0].Address, addressValue)
	}
}

func TestDiagnoseDeploymentNormalizesMetadataAndImmutableSlots(t *testing.T) {
	t.Parallel()

	manifest := []byte(`{
		"schemaVersion": 1,
		"network": "Arc Testnet",
		"chainId": 5042002,
		"contracts": {
			"Configured": {
				"address": "0x2222222222222222222222222222222222222222",
				"artifact": "Configured.json"
			}
		}
	}`)
	address := addressProbeFunc(func(
		context.Context,
		string,
	) (doctor.AddressSnapshot, error) {
		return doctor.AddressSnapshot{
			BalanceBaseUnits: big.NewInt(0),
			Code: []byte{
				0x60, 0xaa, 0xbb, 0x60,
				0xa1, 0x02, 0x00, 0x02,
			},
		}, nil
	})
	loader := func(string) ([]byte, error) {
		return []byte(`{
			"deployedBytecode": {
				"object": "0x60000060a1010002",
				"immutableReferences": {
					"0": [{"start": 1, "length": 2}]
				}
			}
		}`), nil
	}

	report, err := doctor.New(
		arcNetworkProbe(),
		doctor.WithAddressProbe(address),
		doctor.WithArtifactLoader(loader),
	).Diagnose(context.Background(), doctor.Request{
		Kind: doctor.DeploymentCheck,
		Deployment: &doctor.DeploymentInput{
			Name:    "deployment.json",
			BaseDir: "/project",
			Data:    manifest,
		},
	})
	if err != nil {
		t.Fatalf("Diagnose() error = %v", err)
	}
	if report.HasErrors() {
		t.Fatalf("HasErrors() = true, findings = %#v", report.Findings)
	}
	if !hasFinding(report, "ARC-DEP-014") {
		t.Fatalf("Findings = %#v, want ARC-DEP-014", report.Findings)
	}
	if report.Deployment.Contracts[0].ArtifactComparison !=
		doctor.ArtifactComparisonNormalized {
		t.Errorf(
			"ArtifactComparison = %q, want %q",
			report.Deployment.Contracts[0].ArtifactComparison,
			doctor.ArtifactComparisonNormalized,
		)
	}
}

func TestDiagnoseDeploymentReportsBytecodeMismatch(t *testing.T) {
	t.Parallel()

	manifest := []byte(`{
		"schemaVersion": 1,
		"network": "Arc Testnet",
		"chainId": 5042002,
		"contracts": {
			"WrongBuild": {
				"address": "0x3333333333333333333333333333333333333333",
				"artifact": "WrongBuild.json"
			}
		}
	}`)
	address := addressProbeFunc(func(
		context.Context,
		string,
	) (doctor.AddressSnapshot, error) {
		return doctor.AddressSnapshot{
			BalanceBaseUnits: big.NewInt(0),
			Code:             []byte{0x60, 0x02},
		}, nil
	})
	loader := func(string) ([]byte, error) {
		return []byte(`{
			"deployedBytecode": {
				"object": "0x6001"
			}
		}`), nil
	}

	report, err := doctor.New(
		arcNetworkProbe(),
		doctor.WithAddressProbe(address),
		doctor.WithArtifactLoader(loader),
	).Diagnose(context.Background(), doctor.Request{
		Kind: doctor.DeploymentCheck,
		Deployment: &doctor.DeploymentInput{
			Name:    "deployment.json",
			BaseDir: "/project",
			Data:    manifest,
		},
	})
	if err != nil {
		t.Fatalf("Diagnose() error = %v", err)
	}
	if !report.HasErrors() || !hasFinding(report, "ARC-DEP-015") {
		t.Fatalf("Findings = %#v, want ARC-DEP-015 error", report.Findings)
	}
}

func TestDiagnoseDeploymentAcceptsFoundryBroadcast(t *testing.T) {
	t.Parallel()

	const (
		addressValue = "0x4444444444444444444444444444444444444444"
		hashValue    = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	)
	broadcast := []byte(`{
		"chain": "5042002",
		"transactions": [
			{
				"hash": "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
				"transactionType": "CREATE",
				"contractName": "Counter",
				"contractAddress": "0x4444444444444444444444444444444444444444",
				"additionalContracts": []
			}
		],
		"receipts": []
	}`)
	address := addressProbeFunc(func(
		context.Context,
		string,
	) (doctor.AddressSnapshot, error) {
		return doctor.AddressSnapshot{
			BalanceBaseUnits: big.NewInt(0),
			Code:             []byte{0x60, 0x01},
		}, nil
	})
	transaction := transactionProbeFunc(func(
		context.Context,
		string,
	) (doctor.TransactionSnapshot, error) {
		return doctor.TransactionSnapshot{
			Found:          true,
			ValueBaseUnits: big.NewInt(0),
			Receipt: &doctor.TransactionReceiptSnapshot{
				Status:          1,
				ContractAddress: addressValue,
			},
		}, nil
	})

	report, err := doctor.New(
		arcNetworkProbe(),
		doctor.WithAddressProbe(address),
		doctor.WithTransactionProbe(transaction),
	).Diagnose(context.Background(), doctor.Request{
		Kind: doctor.DeploymentCheck,
		Deployment: &doctor.DeploymentInput{
			Name: "run-latest.json",
			Data: broadcast,
		},
	})
	if err != nil {
		t.Fatalf("Diagnose() error = %v", err)
	}
	if report.HasErrors() {
		t.Fatalf("HasErrors() = true, findings = %#v", report.Findings)
	}
	if report.Deployment == nil || report.Deployment.Format != "foundry-broadcast" {
		t.Fatalf("Deployment = %#v, want Foundry format", report.Deployment)
	}
	if report.Deployment.Contracts[0].TransactionHash != hashValue {
		t.Errorf(
			"TransactionHash = %q, want %q",
			report.Deployment.Contracts[0].TransactionHash,
			hashValue,
		)
	}
}
