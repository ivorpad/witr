//go:build windows

package proc

import "github.com/pranshuparmar/witr/pkg/model"

// CollectFacts returns no facts on Windows, which has no zombie processes or
// Unix sessions, so only the checks that use the process list itself apply.
func CollectFacts(procs []model.Process) map[int]ProcessFacts { return nil }
