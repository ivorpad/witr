package suspects

import (
	"testing"
	"time"

	"github.com/pranshuparmar/witr/internal/proc"
	"github.com/pranshuparmar/witr/pkg/model"
)

var now = time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)

func p(pid, ppid int, health, cmd string, started time.Duration) model.Process {
	return model.Process{PID: pid, PPID: ppid, Health: health, Command: cmd, Cmdline: cmd, User: "u", StartedAt: now.Add(-started)}
}

func codes(s Suspect) []string {
	out := make([]string, len(s.Reasons))
	for i, r := range s.Reasons {
		out[i] = r.Code
	}
	return out
}

func find(list []Suspect, pid int) (Suspect, bool) {
	for _, s := range list {
		if s.PID == pid {
			return s, true
		}
	}
	return Suspect{}, false
}

func TestZombiesGroupsByParentAndDropsReaped(t *testing.T) {
	first := []model.Process{
		p(10, 1, "", "server", time.Hour),
		p(11, 10, "zombie", "<defunct>", 30*time.Minute),
		p(12, 10, "zombie", "<defunct>", 20*time.Minute),
		p(20, 1, "", "other", time.Hour),
		p(21, 20, "zombie", "<defunct>", time.Minute), // reaped before the second look
	}
	second := []model.Process{first[0], first[1], first[2], first[3]}

	got := Zombies(first, second)
	if len(got) != 1 || got[0].PID != 10 || len(got[0].Zombies) != 2 {
		t.Fatalf("want parent 10 with 2 zombies, got %+v", got)
	}
	if !got[0].Oldest().Equal(now.Add(-30 * time.Minute)) {
		t.Errorf("oldest = %v", got[0].Oldest())
	}
	if all := Zombies(first, nil); len(all) != 2 {
		t.Errorf("without a second snapshot every zombie counts, got %d parents", len(all))
	}
}

func TestZombieReusedPIDIsNotPersistent(t *testing.T) {
	first := []model.Process{p(10, 1, "", "server", time.Hour), p(11, 10, "zombie", "<defunct>", time.Hour)}
	second := []model.Process{first[0], p(11, 10, "zombie", "<defunct>", time.Second)}
	if got := Zombies(first, second); len(got) != 0 {
		t.Fatalf("a PID reused by a new zombie must not count, got %+v", got)
	}
}

func TestFindZombieParentNeedsGraceAndSkipsInit(t *testing.T) {
	procs := []model.Process{
		p(10, 1, "", "leaky", time.Hour),
		p(11, 10, "zombie", "<defunct>", 10*time.Minute),
		p(20, 1, "", "busy", time.Hour),
		p(21, 20, "zombie", "<defunct>", time.Minute), // too recent to blame the parent
		p(31, 1, "zombie", "<defunct>", time.Hour),    // init reaps on its own schedule
	}
	got := Find(procs, procs, nil, 0, now)
	if s, ok := find(got, 10); !ok || codes(s)[0] != ReasonZombieParent || !s.Shown() {
		t.Errorf("parent 10 should be a shown zombie-parent suspect: %+v", got)
	}
	for _, pid := range []int{20, 1, 31, 11} {
		if _, ok := find(got, pid); ok {
			t.Errorf("pid %d should not be a suspect", pid)
		}
	}
}

func TestFindStoppedOnlyWhenItLasts(t *testing.T) {
	first := []model.Process{p(10, 5, "stopped", "vim", time.Hour), p(11, 5, "stopped", "less", time.Hour)}
	second := []model.Process{first[0], p(11, 5, "", "less", time.Hour)}
	got := Find(first, second, nil, 0, now)
	if s, ok := find(got, 10); !ok || codes(s)[0] != ReasonStopped {
		t.Errorf("10 stayed stopped and should be reported: %+v", got)
	}
	if _, ok := find(got, 11); ok {
		t.Error("11 was resumed and should not be reported")
	}
}

func TestFindDeletedFilesAreStrong(t *testing.T) {
	procs := []model.Process{p(10, 1, "", "a", time.Hour), p(11, 1, "", "b", time.Hour), p(12, 1, "zombie", "<defunct>", time.Hour)}
	facts := map[int]proc.ProcessFacts{
		10: {ExeDeleted: true},
		11: {DeletedCwd: "/tmp/gone"},
		12: {ExeDeleted: true}, // zombies have no executable to speak of
	}
	got := Find(procs, nil, facts, 0, now)
	if s, ok := find(got, 10); !ok || !s.Shown() || codes(s)[0] != ReasonExeDeleted {
		t.Errorf("10: %+v", got)
	}
	if s, ok := find(got, 11); !ok || !s.Shown() || codes(s)[0] != ReasonCwdDeleted {
		t.Errorf("11: %+v", got)
	}
	if _, ok := find(got, 12); ok {
		t.Error("a zombie is reported through its parent, not on its own")
	}
}

func TestFindDetachedIsWeakUntilDuplicated(t *testing.T) {
	procs := []model.Process{
		p(1, 0, "", "init", 48*time.Hour),
		p(50, 1, "", "agent daemon", time.Hour),
		p(60, 1, "", "agent daemon", 2*time.Hour),
		p(70, 1, "", "crash handler", time.Hour),
		p(80, 1, "", "service", time.Hour),     // its own session leader
		p(90, 1, "", "launchd job", time.Hour), // shares init's session
		p(100, 99, "", "shell child", time.Hour),
		p(99, 1, "", "shell", time.Hour), // session leader still alive
	}
	facts := map[int]proc.ProcessFacts{
		50:  {Session: 49},
		60:  {Session: 59},
		70:  {Session: 69},
		80:  {Session: 80},
		90:  {Session: 1},
		99:  {Session: 99},
		100: {Session: 99},
	}
	got := Find(procs, nil, facts, 0, now)
	for _, pid := range []int{50, 60} {
		s, ok := find(got, pid)
		if !ok || !s.Shown() || len(s.Reasons) != 2 || s.Reasons[1].Code != ReasonDuplicate {
			t.Errorf("%d should be detached + duplicate and shown: %+v", pid, s)
		}
	}
	if s, ok := find(got, 70); !ok || s.Shown() {
		t.Errorf("70 is detached only: listed but hidden by default, got %+v ok=%v", s, ok)
	}
	for _, pid := range []int{80, 90, 99, 100} {
		if _, ok := find(got, pid); ok {
			t.Errorf("%d should not be a suspect", pid)
		}
	}
}

func TestFindDifferentUsersAreNotDuplicates(t *testing.T) {
	a, b := p(50, 1, "", "agent", time.Hour), p(60, 1, "", "agent", time.Hour)
	b.User = "other"
	got := Find([]model.Process{a, b}, nil, map[int]proc.ProcessFacts{50: {Session: 49}, 60: {Session: 59}}, 0, now)
	for _, s := range got {
		if s.Shown() {
			t.Errorf("%d: same command under different users is not a duplicate: %v", s.PID, codes(s))
		}
	}
}

func TestFindSkipsSelfAndSortsStrongFirst(t *testing.T) {
	procs := []model.Process{p(50, 1, "", "x", time.Hour), p(60, 1, "", "x", time.Hour), p(70, 1, "", "y", time.Hour), p(80, 1, "", "me", time.Hour)}
	facts := map[int]proc.ProcessFacts{50: {Session: 49}, 60: {Session: 59}, 70: {DeletedCwd: "/gone"}, 80: {DeletedCwd: "/gone"}}
	got := Find(procs, nil, facts, 80, now)
	if len(got) != 3 || got[0].PID != 70 {
		t.Fatalf("want strong 70 first and self (80) skipped, got %+v", got)
	}
}

func TestAge(t *testing.T) {
	for d, want := range map[time.Duration]string{30 * time.Second: "30s", 5 * time.Minute: "5m", 3 * time.Hour: "3h", 47 * time.Hour: "47h", 50 * time.Hour: "2d"} {
		if got := Age(d); got != want {
			t.Errorf("Age(%v) = %q, want %q", d, got, want)
		}
	}
}

func TestZombieStartJitterStillPersistent(t *testing.T) {
	first := []model.Process{p(10, 1, "", "server", time.Hour), p(11, 10, "zombie", "<defunct>", time.Hour)}
	jittered := first[1]
	jittered.StartedAt = jittered.StartedAt.Add(time.Second)
	if got := Zombies(first, []model.Process{first[0], jittered}); len(got) != 1 {
		t.Fatalf("a start time one second off between reads is the same zombie, got %+v", got)
	}
}
