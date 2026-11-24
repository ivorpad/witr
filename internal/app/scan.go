//go:build linux || darwin || freebsd || windows

package app

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/pranshuparmar/witr/internal/output"
	procpkg "github.com/pranshuparmar/witr/internal/proc"
	"github.com/pranshuparmar/witr/internal/suspects"
	"github.com/pranshuparmar/witr/pkg/model"
	"github.com/spf13/cobra"
)

// resampleDelay is how long to wait before the second process list that
// confirms zombie and stopped processes are not about to be reaped or resumed.
const resampleDelay = time.Second

// runScan handles --zombies and --suspects, which look at every process
// instead of explaining one target.
func runScan(cmd *cobra.Command, args []string) error {
	zombies, suspectsFlag := boolFlag(cmd, "zombies"), boolFlag(cmd, "suspects")
	if zombies && suspectsFlag {
		return withExitCode(ExitInvalidInput, fmt.Errorf("use --zombies or --suspects, not both (--suspects already reports parents holding zombies)"))
	}
	if len(args) > 0 || hasTargetFlag(cmd) {
		return withExitCode(ExitInvalidInput, fmt.Errorf("--zombies and --suspects scan every process and take no target"))
	}

	first, err := procpkg.ListProcesses()
	if err != nil {
		return fmt.Errorf("list processes: %w", err)
	}
	var second []model.Process
	if needsResample(first) {
		time.Sleep(resampleDelay)
		if second, err = procpkg.ListProcesses(); err != nil {
			return fmt.Errorf("list processes: %w", err)
		}
	}
	now := time.Now()
	flags := appFlags{json: boolFlag(cmd, "json"), noColor: boolFlag(cmd, "no-color"), verbose: boolFlag(cmd, "verbose")}
	outw := cmd.OutOrStdout()

	if zombies {
		parents := suspects.Zombies(first, second)
		if flags.json {
			return writeJSON(outw, struct {
				Parents []suspects.ZombieParent
			}{Parents: nonNil(parents)})
		}
		output.RenderZombies(outw, parents, now, useColor(flags, outw))
		return nil
	}

	all := suspects.Find(first, second, procpkg.CollectFacts(first), os.Getpid(), now)
	shown := make([]suspects.Suspect, 0, len(all))
	for _, s := range all {
		if flags.verbose || s.Shown() {
			shown = append(shown, s)
		}
	}
	hidden := len(all) - len(shown)
	if flags.json {
		return writeJSON(outw, struct {
			Suspects []suspects.Suspect
			Hidden   int
		}{Suspects: nonNil(shown), Hidden: hidden})
	}
	output.RenderSuspects(outw, shown, hidden, now, useColor(flags, outw))
	return nil
}

func hasTargetFlag(cmd *cobra.Command) bool {
	for _, name := range []string{"pid", "port", "file", "container"} {
		if v, _ := cmd.Flags().GetStringSlice(name); len(v) > 0 {
			return true
		}
	}
	return false
}

// needsResample reports whether the list holds a zombie or stopped process,
// the two states that are only suspect if they last.
func needsResample(procs []model.Process) bool {
	for _, p := range procs {
		if p.Health == "zombie" || p.Health == "stopped" {
			return true
		}
	}
	return false
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func writeJSON(w interface{ Write([]byte) (int, error) }, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "%s\n", b)
	return err
}
