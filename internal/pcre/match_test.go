package pcre

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"testing"
)

func TestFrozenPHPOracle(t *testing.T) {
	raw, err := os.ReadFile("testdata/php81.json")
	if err != nil {
		t.Fatal(err)
	}
	var oracle struct {
		Cases []struct {
			Name, Pattern, Subject string
			SubjectHex             *string `json:"subject_hex"`
			Match                  bool
			Error                  string
		}
	}
	if err = json.Unmarshal(raw, &oracle); err != nil {
		t.Fatal(err)
	}
	for _, c := range oracle.Cases {
		subject := c.Subject
		if c.SubjectHex != nil {
			decoded, err := hex.DecodeString(*c.SubjectHex)
			if err != nil {
				t.Fatal(err)
			}
			subject = string(decoded)
		}
		got, err := Match(c.Pattern, subject)
		kind := ""
		var execution *ExecutionError
		if errors.As(err, &execution) {
			kind = "execution"
		} else if err != nil {
			kind = "compile"
		}
		if got != c.Match || kind != c.Error {
			t.Errorf("%s: got (%t, %q, %v), want (%t, %q)", c.Name, got, kind, err, c.Match, c.Error)
		}
	}
	t.Logf("%d frozen PHP cases", len(oracle.Cases))
}

func TestConcurrentMatches(t *testing.T) {
	var workers sync.WaitGroup
	for range 16 {
		workers.Go(func() {
			for range 20 {
				matched, err := Match(`/^(?<part>a(?&part)?b)$/`, "aaabbb")
				if err != nil || !matched {
					t.Errorf("concurrent match: %t, %v", matched, err)
				}
			}
		})
	}
	workers.Wait()
}
