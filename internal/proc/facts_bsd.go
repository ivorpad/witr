//go:build darwin || freebsd

package proc

import "github.com/pranshuparmar/witr/pkg/model"

// CollectFacts reads each process's session with getsid(2) and adds the
// executable and working directory checks from fileFacts. Values that can't
// be read are left at zero, meaning unknown.
func CollectFacts(procs []model.Process) map[int]ProcessFacts {
	files := fileFacts()
	facts := make(map[int]ProcessFacts, len(procs))
	for _, p := range procs {
		f := files[p.PID]
		f.Session = sessionID(p.PID)
		facts[p.PID] = f
	}
	return facts
}
