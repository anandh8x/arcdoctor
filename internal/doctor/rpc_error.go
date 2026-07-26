package doctor

import "fmt"

type RPCErrorKind string

const (
	RPCErrorUnavailable   RPCErrorKind = "unavailable"
	RPCErrorUnsupported   RPCErrorKind = "unsupported"
	RPCErrorRequestFailed RPCErrorKind = "request_failed"
)

// RPCOperationError preserves which read-only RPC operation failed and how the
// adapter classified it. The Doctor converts expected endpoint failures into
// evidence-backed findings while leaving unrelated internal errors distinct.
type RPCOperationError struct {
	Method string
	Kind   RPCErrorKind
	Err    error
}

func (e *RPCOperationError) Error() string {
	if e == nil {
		return "RPC operation failed"
	}
	if e.Method == "" {
		return fmt.Sprintf("RPC operation failed: %v", e.Err)
	}
	return fmt.Sprintf("%s failed: %v", e.Method, e.Err)
}

func (e *RPCOperationError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}
