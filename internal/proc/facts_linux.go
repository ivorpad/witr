//go:build linux

package proc

import (
	"fmt"
	"os"
	"strings"

	"github.com/pranshuparmar/witr/pkg/model"
)

// CollectFacts reads the session, executable and working directory state of
// each process from /proc. Reads that fail (another user's process without
// privileges, or a process that just exited) leave the fields at their zero
// values, which the suspects check treats as unknown.
func CollectFacts(procs []model.Process) map[int]ProcessFacts {
	facts := make(map[int]ProcessFacts, len(procs))
	for _, p := range procs {
		f := ProcessFacts{Session: p.Session, ExeDeleted: isBinaryDeleted(p.PID)}
		if cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", p.PID)); err == nil {
			if path, ok := strings.CutSuffix(cwd, " (deleted)"); ok {
				f.DeletedCwd = path
			}
		}
		facts[p.PID] = f
	}
	return facts
}
