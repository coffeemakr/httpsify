package simple_test

import "testing"
import "github.com/coffeemakr/httpsify/simple"

func TestRules(t *testing.T) {
	result, ok := simple.SimpleRules.Rewrite("http://test.github.com")
	if !ok {
		t.Fail()
	}
	if result != "https://test.github.com" {
		t.Fail()
	}
}
