package libinjection

import "testing"

func TestSqli(t *testing.T) {
	sqli, _ := IsSqli([]byte("' or ''='"))
	if !sqli {
		t.Error("Failed to test sqli")
	}
}
