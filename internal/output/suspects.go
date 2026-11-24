package output

import (
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/pranshuparmar/witr/internal/suspects"
)

// cmdlineWidth caps the command line shown per process; --json has it whole.
const cmdlineWidth = 110

func clip(s string) string {
	if len(s) <= cmdlineWidth {
		return s
	}
	return s[:cmdlineWidth-1] + "…"
}

// paint sanitizes s and, when color is on, wraps it in color. The result is
// an ansiString, so the Printer passes the color codes through untouched.
func paint(color ansiString, s string, on bool) ansiString {
	s = SanitizeTerminalLine(s)
	if !on {
		return ansiString(s)
	}
	return color + ansiString(s) + ColorReset
}

// RenderZombies prints zombies grouped by the parent that has not collected
// them.
func RenderZombies(w io.Writer, parents []suspects.ZombieParent, now time.Time, color bool) {
	p := NewPrinter(w)
	if len(parents) == 0 {
		p.Printf("No zombie processes.\n")
		return
	}
	total := 0
	for _, g := range parents {
		total += len(g.Zombies)
	}
	p.Printf("%s under %s\n\n", pluralCount(total, "zombie process", "zombie processes"), pluralCount(len(parents), "parent", "parents"))
	for _, g := range parents {
		name := g.Cmdline
		if name == "" {
			name = "(parent not visible)"
		}
		oldest := "unknown"
		if o := g.Oldest(); !o.IsZero() {
			oldest = suspects.Age(now.Sub(o)) + " ago"
		}
		pids := make([]string, len(g.Zombies))
		for i, z := range g.Zombies {
			pids[i] = strconv.Itoa(z.PID)
		}
		p.Printf("%s  %s\n", paint(ColorCyan, padPID(g.PID), color), clip(name))
		p.Printf("        %s, oldest started %s: %s\n", pluralCount(len(g.Zombies), "zombie", "zombies"), oldest, paint(ColorDim, strings.Join(pids, " "), color))
	}
	p.Printf("\n%s\n", paint(ColorDim, "Zombies have already exited and can't be killed. They go away when the parent", color))
	p.Printf("%s\n", paint(ColorDim, "collects them or exits, so restart or stop the parent (witr --pid <parent>).", color))
}

// RenderSuspects prints suspect processes with their reasons. hidden is the
// number left out because they have a single weak reason.
func RenderSuspects(w io.Writer, list []suspects.Suspect, hidden int, now time.Time, color bool) {
	p := NewPrinter(w)
	if len(list) == 0 {
		p.Printf("No suspicious processes found.\n")
	} else {
		p.Printf("%s\n\n", pluralCount(len(list), "suspicious process", "suspicious processes"))
	}
	for _, s := range list {
		started := "start unknown"
		if !s.StartedAt.IsZero() {
			started = "started " + suspects.Age(now.Sub(s.StartedAt)) + " ago"
		}
		meta := s.User + ", " + started + ", " + formatBytes(s.MemoryRSS) + ", parent " + strconv.Itoa(s.PPID)
		p.Printf("%s  %s\n", paint(ColorCyan, padPID(s.PID), color), clip(s.Cmdline))
		p.Printf("        %s\n", paint(ColorDim, meta, color))
		for _, r := range s.Reasons {
			c := ColorDimYellow
			if r.Strong {
				c = ColorRed
			}
			p.Printf("        %s %s\n", paint(c, r.Code+":", color), r.Detail)
		}
		p.Printf("\n")
	}
	if hidden > 0 {
		p.Printf("%s\n", paint(ColorDim, pluralCount(hidden, "more process has", "more processes have")+" a single weak signal; --verbose lists them.", color))
	}
	if len(list) > 0 {
		p.Printf("%s\n", paint(ColorDim, "witr --pid <PID> explains where a process came from.", color))
	}
}

func padPID(pid int) string {
	return strings.Repeat(" ", max(0, 6-len(strconv.Itoa(pid)))) + strconv.Itoa(pid)
}

func pluralCount(n int, one, many string) string {
	if n == 1 {
		return strconv.Itoa(n) + " " + one
	}
	return strconv.Itoa(n) + " " + many
}
