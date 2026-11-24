package output

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestClipKeepsRunesWhole(t *testing.T) {
	long := strings.Repeat("é", cmdlineWidth+5)
	got := clip(long)
	if !utf8.ValidString(got) || utf8.RuneCountInString(got) != cmdlineWidth {
		t.Errorf("clip produced %d runes, valid=%v", utf8.RuneCountInString(got), utf8.ValidString(got))
	}
	if clip("short") != "short" {
		t.Error("short strings are left alone")
	}
}
