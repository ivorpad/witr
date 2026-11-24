package proc

// listHealth maps a process state code (the ps STAT column or the state field
// of /proc/<pid>/stat) to the Health value a full read would give, for the two
// states the process list can report without reading each process: "zombie"
// and "stopped". It returns "" for every other state. A lowercase 't' on Linux
// means stopped by a debugger, which is deliberate, so it is not reported.
func listHealth(state string) string {
	if state == "" {
		return ""
	}
	switch state[0] {
	case 'Z':
		return "zombie"
	case 'T':
		return "stopped"
	}
	return ""
}
