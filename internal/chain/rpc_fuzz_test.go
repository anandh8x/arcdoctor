package chain_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/anandh8x/arcdoctor/internal/chain"
)

func FuzzRPCProbeMalformedResponsesDoNotPanic(f *testing.F) {
	f.Add([]byte(`{"jsonrpc":"2.0","id":1,"result":"0x4cef52"}`))
	f.Add([]byte(`{"jsonrpc":"2.0","id":1,"result":null}`))
	f.Add([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}`))
	f.Add([]byte(`not-json`))

	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > 64<<10 {
			t.Skip()
		}
		client := &http.Client{
			Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Header: http.Header{
						"Content-Type": []string{"application/json"},
					},
					Body: io.NopCloser(bytes.NewReader(body)),
				}, nil
			}),
		}
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
		defer cancel()
		_, _ = chain.NewRPCProbe(
			"http://arcdoctor.invalid",
			chain.WithHTTPClient(client),
		).NetworkSnapshot(ctx)
	})
}
