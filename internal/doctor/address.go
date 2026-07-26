package doctor

import (
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

type addressValidation int

const (
	addressMalformed addressValidation = iota
	addressValid
	addressChecksumInvalid
)

func validateAddress(value string) (string, addressValidation) {
	if !common.IsHexAddress(value) {
		return "", addressMalformed
	}
	normalized := common.HexToAddress(value).Hex()
	body := value
	if strings.HasPrefix(body, "0x") || strings.HasPrefix(body, "0X") {
		body = body[2:]
	}
	lower := strings.ToLower(body)
	upper := strings.ToUpper(body)
	if body != lower && body != upper && "0x"+body != normalized {
		return normalized, addressChecksumInvalid
	}
	return normalized, addressValid
}
