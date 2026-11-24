package proc

import "testing"

func TestListHealth(t *testing.T) {
	for state, want := range map[string]string{"Z": "zombie", "Z+": "zombie", "T": "stopped", "TN": "stopped", "t": "", "S": "", "Ss": "", "R+": "", "": ""} {
		if got := listHealth(state); got != want {
			t.Errorf("listHealth(%q) = %q, want %q", state, got, want)
		}
	}
}
