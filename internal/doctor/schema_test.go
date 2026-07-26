package doctor_test

import (
	"encoding/json"
	"os"
	"testing"
)

func TestPublishedReportSchemaIsValidJSON(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("../../schema/report-v1.schema.json")
	if err != nil {
		t.Fatalf("read report schema: %v", err)
	}
	var schema map[string]any
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatalf("decode report schema: %v", err)
	}
	if schema["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
		t.Errorf("$schema = %q", schema["$schema"])
	}
	if schema["title"] != "Arc Doctor report" {
		t.Errorf("title = %q", schema["title"])
	}
}
