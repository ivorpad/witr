//go:build linux || darwin || freebsd

package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/spf13/pflag"
)

// runScanArgs executes the root command with args and resets the flags it
// may have set, since cobra keeps flag values between Execute calls.
func runScanArgs(t *testing.T, args ...string) (string, error) {
	t.Helper()
	resetTargets := func() {
		for _, name := range []string{"pid", "port", "file", "container"} {
			if f := Root().Flags().Lookup(name); f != nil {
				_ = f.Value.(pflag.SliceValue).Replace(nil)
				f.Changed = false
			}
		}
	}
	resetTargets() // earlier tests in the package may have left targets set
	oldArgs := os.Args
	os.Args = append([]string{"witr"}, args...)
	cmd := Root()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	t.Cleanup(func() {
		os.Args = oldArgs
		cmd.SetArgs(nil)
		for _, name := range []string{"zombies", "suspects", "json", "verbose", "no-color"} {
			_ = cmd.Flags().Set(name, "false")
		}
		resetTargets()
	})
	err := cmd.Execute()
	return out.String(), err
}

func TestScanSuspectsJSONWithSusAlias(t *testing.T) {
	out, err := runScanArgs(t, "--sus", "--json")
	if err != nil {
		t.Fatalf("--sus --json: %v\n%s", err, out)
	}
	var got struct {
		Suspects []map[string]any
		Hidden   *int
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil || got.Suspects == nil || got.Hidden == nil {
		t.Fatalf("want {Suspects: [...], Hidden: n}, got err=%v:\n%s", err, out)
	}
}

func TestScanZombiesJSON(t *testing.T) {
	out, err := runScanArgs(t, "--zombies", "--json")
	if err != nil {
		t.Fatalf("--zombies --json: %v\n%s", err, out)
	}
	var got struct {
		Parents []map[string]any
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil || got.Parents == nil {
		t.Fatalf("want {Parents: [...]}, got err=%v:\n%s", err, out)
	}
}

func TestScanRejectsTargetsAndBothModes(t *testing.T) {
	cases := map[string][]string{
		"not both":        {"--zombies", "--suspects"},
		"take no target":  {"--zombies", "--pid", "1"},
		"take no target ": {"--sus", "nginx"},
	}
	for want, args := range cases {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			_, err := runScanArgs(t, args...)
			var ece *exitCodeError
			if !errors.As(err, &ece) || ece.code != ExitInvalidInput || !strings.Contains(err.Error(), strings.TrimSpace(want)) {
				t.Errorf("want invalid input mentioning %q, got %v", strings.TrimSpace(want), err)
			}
		})
	}
}
