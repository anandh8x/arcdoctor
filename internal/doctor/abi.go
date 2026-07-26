package doctor

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"
	"sort"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

var (
	errorStringSelector = [4]byte{0x08, 0xc3, 0x79, 0xa0}
	panicSelector       = [4]byte{0x4e, 0x48, 0x7b, 0x71}
)

type namedABI struct {
	name string
	abi  abi.ABI
}

type abiCatalog struct {
	entries []namedABI
}

func parseABIs(inputs []ABIInput) (abiCatalog, []Finding) {
	catalog := abiCatalog{}
	findings := make([]Finding, 0)
	for _, input := range inputs {
		parsed, err := parseABI(input.Data)
		if err != nil {
			findings = append(findings, Finding{
				Code:        "ARC-TX-014",
				Severity:    SeverityWarning,
				Confidence:  ConfidenceCertain,
				Title:       "ABI input could not be parsed",
				Explanation: "Transaction inspection continued without using this ABI input.",
				Evidence: []string{
					fmt.Sprintf("ABI source: %s", input.Name),
					fmt.Sprintf("Parse error: %s", err),
				},
				SuggestedActions: []string{
					"Provide a Solidity ABI array or a JSON artifact containing an abi field.",
				},
			})
			continue
		}
		catalog.entries = append(catalog.entries, namedABI{
			name: input.Name,
			abi:  parsed,
		})
	}
	return catalog, findings
}

func parseABI(data []byte) (abi.ABI, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return abi.ABI{}, fmt.Errorf("empty input")
	}

	abiJSON := trimmed
	if trimmed[0] == '{' {
		var artifact struct {
			ABI json.RawMessage `json:"abi"`
		}
		if err := json.Unmarshal(trimmed, &artifact); err != nil {
			return abi.ABI{}, fmt.Errorf("decode artifact JSON: %w", err)
		}
		if len(artifact.ABI) == 0 || bytes.Equal(artifact.ABI, []byte("null")) {
			return abi.ABI{}, fmt.Errorf("artifact does not contain an abi field")
		}
		abiJSON = artifact.ABI
	}

	parsed, err := abi.JSON(bytes.NewReader(abiJSON))
	if err != nil {
		return abi.ABI{}, fmt.Errorf("decode ABI: %w", err)
	}
	return parsed, nil
}

type methodMatch struct {
	source string
	method abi.Method
}

func (c abiCatalog) decodeCall(data []byte) (*DecodedCallEvidence, *Finding) {
	if len(data) < 4 || len(c.entries) == 0 {
		return nil, nil
	}

	matches := make([]methodMatch, 0)
	for _, entry := range c.entries {
		method, err := entry.abi.MethodById(data[:4])
		if err == nil {
			matches = append(matches, methodMatch{
				source: entry.name,
				method: *method,
			})
		}
	}
	if len(matches) == 0 {
		selector := "0x" + hex.EncodeToString(data[:4])
		return nil, &Finding{
			Code:        "ARC-TX-006",
			Severity:    SeverityWarning,
			Confidence:  ConfidenceCertain,
			Title:       "Calldata selector was not found in supplied ABIs",
			Explanation: "The public calldata is preserved, but no supplied ABI identifies this selector.",
			Evidence: []string{
				"Function selector: " + selector,
			},
			SuggestedActions: []string{
				"Supply the ABI for the contract implementation used by this transaction.",
			},
		}
	}

	signatures := uniqueMethodSignatures(matches)
	if len(signatures) > 1 {
		return nil, &Finding{
			Code:        "ARC-TX-013",
			Severity:    SeverityWarning,
			Confidence:  ConfidenceCertain,
			Title:       "Calldata selector is ambiguous across supplied ABIs",
			Explanation: "Multiple function signatures share this selector, so Arc Doctor will not choose one.",
			Evidence: append(
				[]string{"Function selector: 0x" + hex.EncodeToString(data[:4])},
				prefixed("Candidate: ", signatures)...,
			),
			SuggestedActions: []string{
				"Supply only the ABI associated with the transaction destination.",
			},
		}
	}

	match := matches[0]
	values, err := match.method.Inputs.Unpack(data[4:])
	if err != nil {
		return nil, &Finding{
			Code:        "ARC-TX-015",
			Severity:    SeverityWarning,
			Confidence:  ConfidenceCertain,
			Title:       "Calldata arguments did not match the ABI",
			Explanation: "The selector matched a function, but the remaining calldata could not be decoded with its input types.",
			Evidence: []string{
				"Function signature: " + match.method.Sig,
				"ABI source: " + match.source,
				"Decode error: " + err.Error(),
			},
			SuggestedActions: []string{
				"Verify that the ABI matches the deployed implementation.",
			},
		}
	}

	arguments := decodedArguments(match.method.Inputs, values)
	call := &DecodedCallEvidence{
		Signature: match.method.Sig,
		Source:    match.source,
		Arguments: arguments,
	}
	return call, &Finding{
		Code:        "ARC-TX-005",
		Severity:    SeverityInfo,
		Confidence:  ConfidenceCertain,
		Title:       "Transaction calldata decoded",
		Explanation: "A supplied ABI matched the function selector and argument encoding.",
		Evidence: []string{
			"Function signature: " + match.method.Sig,
			"ABI source: " + match.source,
		},
	}
}

type errorMatch struct {
	source string
	err    abi.Error
}

func (c abiCatalog) decodeRevert(data []byte) (RevertEvidence, Finding) {
	raw := "0x" + hex.EncodeToString(data)
	revert := RevertEvidence{
		Kind:    RevertKindUnknown,
		RawData: raw,
	}
	if len(data) >= 4 {
		revert.Selector = "0x" + hex.EncodeToString(data[:4])
	}

	if len(data) >= 4 && bytes.Equal(data[:4], errorStringSelector[:]) {
		message, err := abi.UnpackRevert(data)
		if err == nil {
			revert.Kind = RevertKindError
			revert.Signature = "Error(string)"
			revert.Message = message
			return revert, Finding{
				Code:        "ARC-TX-007",
				Severity:    SeverityInfo,
				Confidence:  ConfidenceCertain,
				Title:       "Solidity error string decoded",
				Explanation: "The replay returned standard Error(string) revert data.",
				Evidence: []string{
					"Revert signature: Error(string)",
					"Revert message: " + message,
					"Raw revert data: " + raw,
				},
			}
		}
	}

	if len(data) >= 4 && bytes.Equal(data[:4], panicSelector[:]) {
		message, err := abi.UnpackRevert(data)
		if err == nil && len(data) >= 36 {
			code := new(big.Int).SetBytes(data[4:36])
			revert.Kind = RevertKindPanic
			revert.Signature = "Panic(uint256)"
			revert.PanicCode = fmt.Sprintf("0x%x", code)
			revert.Message = message
			return revert, Finding{
				Code:        "ARC-TX-008",
				Severity:    SeverityInfo,
				Confidence:  ConfidenceCertain,
				Title:       "Solidity panic decoded",
				Explanation: "The replay returned standard Panic(uint256) revert data.",
				Evidence: []string{
					"Revert signature: Panic(uint256)",
					"Panic code: " + revert.PanicCode,
					"Panic reason: " + message,
					"Raw revert data: " + raw,
				},
			}
		}
	}

	if len(data) >= 4 {
		var selector [4]byte
		copy(selector[:], data[:4])
		matches := make([]errorMatch, 0)
		for _, entry := range c.entries {
			matched, err := entry.abi.ErrorByID(selector)
			if err == nil {
				matches = append(matches, errorMatch{
					source: entry.name,
					err:    *matched,
				})
			}
		}
		signatures := uniqueErrorSignatures(matches)
		if len(signatures) > 1 {
			revert.Ambiguous = true
			revert.Candidates = signatures
			return revert, Finding{
				Code:        "ARC-TX-010",
				Severity:    SeverityWarning,
				Confidence:  ConfidenceCertain,
				Title:       "Revert selector is ambiguous",
				Explanation: "Multiple supplied custom errors share this selector, so Arc Doctor will not choose one.",
				Evidence: append(
					[]string{
						"Revert selector: " + revert.Selector,
						"Raw revert data: " + raw,
					},
					prefixed("Candidate: ", signatures)...,
				),
				SuggestedActions: []string{
					"Supply only the ABI associated with the transaction destination.",
				},
			}
		}
		if len(matches) > 0 {
			match := matches[0]
			values, err := match.err.Inputs.Unpack(data[4:])
			if err == nil {
				revert.Kind = RevertKindCustom
				revert.Signature = match.err.Sig
				revert.Source = match.source
				revert.Arguments = decodedArguments(match.err.Inputs, values)
				return revert, Finding{
					Code:        "ARC-TX-009",
					Severity:    SeverityInfo,
					Confidence:  ConfidenceCertain,
					Title:       "Custom Solidity error decoded",
					Explanation: "A supplied ABI matched the revert selector and argument encoding.",
					Evidence: []string{
						"Revert signature: " + match.err.Sig,
						"ABI source: " + match.source,
						"Raw revert data: " + raw,
					},
				}
			}
		}
	}

	return revert, Finding{
		Code:        "ARC-TX-010",
		Severity:    SeverityWarning,
		Confidence:  ConfidenceCertain,
		Title:       "Revert data could not be decoded",
		Explanation: "The raw replay response is preserved without assigning a contract-specific meaning.",
		Evidence: []string{
			"Raw revert data: " + raw,
		},
		SuggestedActions: []string{
			"Supply the ABI for the contract implementation used by this transaction.",
		},
	}
}

func decodedArguments(arguments abi.Arguments, values []any) []DecodedArgument {
	decoded := make([]DecodedArgument, 0, len(values))
	for index, value := range values {
		name := ""
		typ := ""
		if index < len(arguments) {
			name = arguments[index].Name
			typ = arguments[index].Type.String()
		}
		decoded = append(decoded, DecodedArgument{
			Name:  name,
			Type:  typ,
			Value: formatABIValue(value),
		})
	}
	return decoded
}

func formatABIValue(value any) string {
	switch typed := value.(type) {
	case common.Address:
		return typed.Hex()
	case *big.Int:
		return typed.String()
	case []byte:
		return "0x" + hex.EncodeToString(typed)
	case string:
		return typed
	case bool:
		return fmt.Sprintf("%t", typed)
	}

	reflected := reflect.ValueOf(value)
	if reflected.IsValid() && reflected.Kind() == reflect.Array &&
		reflected.Type().Elem().Kind() == reflect.Uint8 {
		bytesValue := make([]byte, reflected.Len())
		reflect.Copy(reflect.ValueOf(bytesValue), reflected)
		return "0x" + hex.EncodeToString(bytesValue)
	}

	encoded, err := json.Marshal(value)
	if err == nil {
		return string(encoded)
	}
	return fmt.Sprintf("%v", value)
}

func uniqueMethodSignatures(matches []methodMatch) []string {
	values := make([]string, 0, len(matches))
	seen := make(map[string]struct{})
	for _, match := range matches {
		if _, ok := seen[match.method.Sig]; ok {
			continue
		}
		seen[match.method.Sig] = struct{}{}
		values = append(values, match.method.Sig)
	}
	sort.Strings(values)
	return values
}

func uniqueErrorSignatures(matches []errorMatch) []string {
	values := make([]string, 0, len(matches))
	seen := make(map[string]struct{})
	for _, match := range matches {
		if _, ok := seen[match.err.Sig]; ok {
			continue
		}
		seen[match.err.Sig] = struct{}{}
		values = append(values, match.err.Sig)
	}
	sort.Strings(values)
	return values
}

func prefixed(prefix string, values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, prefix+strings.TrimSpace(value))
	}
	return result
}
