package proc

// ProcessFacts holds what the suspects check needs about a process beyond the
// process list, collected for every listed process in a few bulk reads.
type ProcessFacts struct {
	// Session is the process's session ID, or 0 when it can't be read.
	Session int
	// ExeDeleted is set when the executable file was removed or replaced on
	// disk after the process started.
	ExeDeleted bool
	// DeletedCwd is the former path of a working directory that has since
	// been removed or replaced, or "" when it still exists or can't be read.
	DeletedCwd string
}
