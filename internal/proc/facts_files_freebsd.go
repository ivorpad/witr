//go:build freebsd

package proc

// fileFacts is not implemented on FreeBSD, which ships without lsof.
func fileFacts() map[int]ProcessFacts { return nil }
