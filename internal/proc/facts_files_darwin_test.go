//go:build darwin

package proc

import "testing"

func TestParseFileFacts(t *testing.T) {
	disk := map[string]uint64{"/home/app": 100, "/usr/bin/tool": 200, "/opt/new/bin": 999, "/lib/a.dylib": 1}
	stat := func(path string) (uint64, bool) { ino, ok := disk[path]; return ino, ok }
	out := "p10\nfcwd\ni100\nn/home/app\nftxt\ni200\nn/usr/bin/tool\nftxt\ni2\nn/lib/missing.dylib\n" +
		"p20\nfcwd\ni5\nn/tmp/removed\nftxt\ni300\nn/opt/new/bin\n" +
		"p30\nfcwd\ni0\nn/home/app\nftxt\ni1\nn/lib/a.dylib\n"
	got := parseFileFacts(out, stat)

	if f, ok := got[10]; ok {
		t.Errorf("pid 10 has its files and a missing library is not its executable: %+v", f)
	}
	if f := got[20]; f.DeletedCwd != "/tmp/removed" || !f.ExeDeleted {
		t.Errorf("pid 20: removed cwd and a replaced executable (inode 300 vs 999), got %+v", f)
	}
	if f, ok := got[30]; ok {
		t.Errorf("pid 30: unknown inode (0) must not count as replaced: %+v", f)
	}
}
