//go:build darwin

package proc

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

// fileFacts lists the working directory and executable of every process the
// user can see with a single lsof call, and reports those that are gone.
func fileFacts() map[int]ProcessFacts {
	cmd := exec.Command("lsof", "-nP", "-w", "-d", "cwd,txt", "-Fpfin")
	cmd.Env = buildEnvForPS()
	out, _ := cmd.Output() // lsof exits 1 when some processes can't be read
	return parseFileFacts(string(out), statInode)
}

// statInode reports the inode now at path and whether the path exists.
func statInode(path string) (uint64, bool) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, false
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return st.Ino, true
	}
	return 0, true
}

// parseFileFacts reads lsof -F output (p<pid>, f<fd>, i<inode>, n<path>). lsof
// keeps reporting the path a file was opened by, so a path that no longer
// exists, or now holds a different inode, was deleted or replaced. The first
// txt entry of a process is its executable; later ones are libraries.
func parseFileFacts(out string, stat func(string) (uint64, bool)) map[int]ProcessFacts {
	facts := make(map[int]ProcessFacts)
	pid, fd, seenTxt := 0, "", false
	var inode uint64
	for _, line := range strings.Split(out, "\n") {
		if len(line) < 2 {
			continue
		}
		val := line[1:]
		switch line[0] {
		case 'p':
			pid, _ = strconv.Atoi(val)
			fd, seenTxt = "", false
		case 'f':
			fd, inode = val, 0
		case 'i':
			inode, _ = strconv.ParseUint(val, 10, 64)
		case 'n':
			if pid <= 0 || !strings.HasPrefix(val, "/") {
				continue
			}
			isExe := fd == "txt" && !seenTxt
			if fd == "txt" {
				seenTxt = true
			}
			if fd != "cwd" && !isExe {
				continue
			}
			now, exists := stat(val)
			if exists && (inode == 0 || now == 0 || now == inode) {
				continue
			}
			f := facts[pid]
			if fd == "cwd" {
				f.DeletedCwd = val
			} else {
				f.ExeDeleted = true
			}
			facts[pid] = f
		}
	}
	return facts
}
