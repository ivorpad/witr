// Package suspects finds zombie processes and processes that look left
// behind, from the process list plus a few bulk reads. Every rule here is a
// generic process property (state, session, executable, working directory),
// not a list of known program names.
package suspects

import (
	"fmt"
	"sort"
	"time"

	"github.com/pranshuparmar/witr/internal/proc"
	"github.com/pranshuparmar/witr/pkg/model"
)

// Zombie is a process that has exited but whose parent has not collected its
// exit status. StartedAt is when the process started, not when it exited:
// the OS does not record the time of death.
type Zombie struct {
	PID       int
	StartedAt time.Time
}

// ZombieParent is a process holding one or more zombie children.
type ZombieParent struct {
	PID     int
	Command string
	Cmdline string
	User    string
	Zombies []Zombie
}

// Reason codes. Strong reasons are enough on their own to list a process;
// weak ones only in combination.
const (
	ReasonZombieParent = "zombie-parent"
	ReasonStopped      = "stopped"
	ReasonExeDeleted   = "exe-deleted"
	ReasonCwdDeleted   = "cwd-deleted"
	ReasonDetached     = "detached"
	ReasonDuplicate    = "duplicate"
)

// Reason explains one thing that makes a process suspect.
type Reason struct {
	Code   string
	Detail string
	Strong bool
}

// Suspect is a process with at least one reason to look at it.
type Suspect struct {
	PID        int
	PPID       int
	User       string
	Command    string
	Cmdline    string
	StartedAt  time.Time
	CPUPercent float64
	MemoryRSS  uint64
	Reasons    []Reason
}

// Strong reports whether any reason is strong on its own.
func (s Suspect) Strong() bool {
	for _, r := range s.Reasons {
		if r.Strong {
			return true
		}
	}
	return false
}

// Shown reports whether s is listed by default: one strong reason or at
// least two weak ones.
func (s Suspect) Shown() bool {
	return s.Strong() || len(s.Reasons) >= 2
}

// persistent returns the PIDs whose Health is want in first and, when a
// second snapshot was taken, still in second with the same start time. A
// zombie or stopped process seen only once may be a moment from being reaped
// or resumed; one still there a second later is not.
func persistent(first, second []model.Process, want string) map[int]model.Process {
	again := map[int]model.Process{}
	if second != nil {
		for _, p := range second {
			if p.Health == want {
				again[p.PID] = p
			}
		}
	}
	out := map[int]model.Process{}
	for _, p := range first {
		if p.Health != want {
			continue
		}
		if second != nil {
			q, ok := again[p.PID]
			if !ok || q.PPID != p.PPID || !sameStart(q.StartedAt, p.StartedAt) {
				continue
			}
		}
		out[p.PID] = p
	}
	return out
}

// sameStart reports whether two start times read from separate process lists
// name the same process. They are derived from boot time, which the OS may
// report a second off between reads, while a reused PID starts much later.
func sameStart(a, b time.Time) bool {
	d := a.Sub(b)
	return d < 2*time.Second && d > -2*time.Second
}

// Zombies groups the zombies present in both snapshots by parent, parents
// with the most zombies first. Pass a nil second snapshot to use first alone.
func Zombies(first, second []model.Process) []ZombieParent {
	byPID := make(map[int]model.Process, len(first))
	for _, p := range first {
		byPID[p.PID] = p
	}
	groups := map[int]*ZombieParent{}
	for _, z := range persistent(first, second, "zombie") {
		g, ok := groups[z.PPID]
		if !ok {
			parent := byPID[z.PPID]
			g = &ZombieParent{PID: z.PPID, Command: parent.Command, Cmdline: parent.Cmdline, User: parent.User}
			groups[z.PPID] = g
		}
		g.Zombies = append(g.Zombies, Zombie{PID: z.PID, StartedAt: z.StartedAt})
	}
	out := make([]ZombieParent, 0, len(groups))
	for _, g := range groups {
		sort.Slice(g.Zombies, func(i, j int) bool { return g.Zombies[i].PID < g.Zombies[j].PID })
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool {
		if len(out[i].Zombies) != len(out[j].Zombies) {
			return len(out[i].Zombies) > len(out[j].Zombies)
		}
		return out[i].PID < out[j].PID
	})
	return out
}

// Oldest returns the earliest known start time among g's zombies.
func (g ZombieParent) Oldest() time.Time {
	var oldest time.Time
	for _, z := range g.Zombies {
		if !z.StartedAt.IsZero() && (oldest.IsZero() || z.StartedAt.Before(oldest)) {
			oldest = z.StartedAt
		}
	}
	return oldest
}

// zombieGrace is how long a zombie must have existed, at least, before its
// parent counts as failing to collect it. The OS doesn't record when a process
// exited, but a zombie can't have died before it started, so one that started
// within this window may simply not have been collected yet.
const zombieGrace = 5 * time.Minute

// Find returns every process with at least one reason, sorted with strong
// reasons first. Callers decide whether to show the weak-only ones (Shown).
// self is the caller's own PID, which is never reported.
func Find(first, second []model.Process, facts map[int]proc.ProcessFacts, self int, now time.Time) []Suspect {
	alive := make(map[int]bool, len(first))
	for _, p := range first {
		alive[p.PID] = true
	}
	reasons := map[int][]Reason{}
	add := func(pid int, r Reason) { reasons[pid] = append(reasons[pid], r) }

	for _, g := range Zombies(first, second) {
		// init and subreapers collect zombies on their own schedule.
		if g.PID <= 1 || !alive[g.PID] {
			continue
		}
		if o := g.Oldest(); o.IsZero() || now.Sub(o) < zombieGrace {
			continue
		}
		detail := fmt.Sprintf("has %d zombie %s it has not collected (oldest started %s ago)",
			len(g.Zombies), plural(len(g.Zombies), "child", "children"), Age(now.Sub(g.Oldest())))
		add(g.PID, Reason{Code: ReasonZombieParent, Detail: detail, Strong: true})
	}
	for pid := range persistent(first, second, "stopped") {
		add(pid, Reason{Code: ReasonStopped, Detail: "is stopped (suspended) and not running", Strong: true})
	}

	detached := map[int]bool{}
	for _, p := range first {
		if p.Health == "zombie" {
			continue
		}
		f := facts[p.PID]
		if f.ExeDeleted {
			add(p.PID, Reason{Code: ReasonExeDeleted, Detail: "its executable was deleted or replaced on disk, so it still runs the old binary", Strong: true})
		}
		if f.DeletedCwd != "" {
			add(p.PID, Reason{Code: ReasonCwdDeleted, Detail: "its working directory was deleted: " + f.DeletedCwd, Strong: true})
		}
		// A process normally shares its session with the shell or service
		// that started it. When the session leader is gone and the process
		// never started a session of its own, it outlived whatever started it.
		if f.Session > 1 && f.Session != p.PID && !alive[f.Session] {
			detached[p.PID] = true
			add(p.PID, Reason{Code: ReasonDetached, Detail: fmt.Sprintf("outlived the session that started it (session leader %d has exited)", f.Session)})
		}
	}

	// Identical detached copies usually mean each run started a new one and
	// none was stopped.
	copies := map[string][]int{}
	for _, p := range first {
		if detached[p.PID] {
			key := p.User + "\x00" + p.Cmdline
			copies[key] = append(copies[key], p.PID)
		}
	}
	for _, pids := range copies {
		if len(pids) < 2 {
			continue
		}
		for _, pid := range pids {
			add(pid, Reason{Code: ReasonDuplicate, Detail: fmt.Sprintf("is one of %d identical copies that outlived their sessions", len(pids))})
		}
	}

	out := make([]Suspect, 0, len(reasons))
	for _, p := range first {
		rs, ok := reasons[p.PID]
		if !ok || p.PID == self {
			continue
		}
		out = append(out, Suspect{
			PID: p.PID, PPID: p.PPID, User: p.User, Command: p.Command, Cmdline: p.Cmdline,
			StartedAt: p.StartedAt, CPUPercent: p.CPUPercent, MemoryRSS: p.MemoryRSS, Reasons: rs,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Strong() != b.Strong() {
			return a.Strong()
		}
		if len(a.Reasons) != len(b.Reasons) {
			return len(a.Reasons) > len(b.Reasons)
		}
		if a.MemoryRSS != b.MemoryRSS {
			return a.MemoryRSS > b.MemoryRSS
		}
		return a.PID < b.PID
	})
	return out
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// Age renders a duration as a short "19d", "5h", "12m" or "30s".
func Age(d time.Duration) string {
	switch {
	case d >= 48*time.Hour:
		return fmt.Sprintf("%dd", int(d.Hours())/24)
	case d >= time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	case d >= time.Minute:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	default:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
}
