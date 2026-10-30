package testsupport

import (
	_ "embed"
	"encoding/json"
	"testing"
)

//go:embed testdata/installed-options.json
var installedOptions []byte

// InstalledOptions is the frozen 6.0.2 import-options result for the synthetic
// 2026 installation, including SetupController's canonical site URL.
func InstalledOptions(t *testing.T) map[string]string {
	t.Helper()
	var options map[string]string
	if err := json.Unmarshal(installedOptions, &options); err != nil {
		t.Fatal(err)
	}
	return options
}
