package libinjection

import "testing"

func TestBasicSqli(t *testing.T) {
	res, _ := IsSqli([]byte("' or ''='"))
	if !res {
		t.Error("failed to find sqli")
	}
}
