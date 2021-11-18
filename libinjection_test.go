package libinjection

import "testing"

func TestLibinjection(t *testing.T) {
	sqli := &Sqli{}
	if is, _ := sqli.libinjection_sqli("' or ''='"); !is {
		t.Error("sql injection not detected")
	}
}
