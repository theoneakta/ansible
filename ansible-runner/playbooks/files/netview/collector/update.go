package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Updates asked for on the Collectors page (Update). The collector runs
// unprivileged and can't replace its own program, so it asks what installed
// it - which downloads the collector from Sentry Lens itself, checks it
// against SHA256SUMS and restarts it. The request carries nothing the
// updater uses: the worst a tampered collector can do is ask for a download.
//
//	systemd  Linux (install.sh): a file in its state folder starts the
//	         sentry-collector-update unit (a .path unit watches for it)
//	task     Windows (install.ps1): a file in ProgramData\SentryLens, which
//	         the "SentryLens collector update" task (SYSTEM) checks for
//	restart  Docker: the container fetches the collector at each start, so
//	         the collector just exits and Docker starts it again
const (
	linuxUpdater = "/usr/local/libexec/sentry-collector-update"
	requestFile  = "update.request"
)

// updater: how this collector can be updated ("" if it can't - installed by
// an installer from before 2.5.0, or by hand).
func updater(cfg Config) string {
	exe, _ := os.Executable()
	switch {
	case runtime.GOOS == "linux" && inDocker() && strings.HasPrefix(exe, "/tmp/"):
		return "restart"
	case runtime.GOOS == "linux" && cfg.StateDir != "" && exists(linuxUpdater):
		return "systemd"
	case runtime.GOOS == "windows" && cfg.StateDir != "" && exists(filepath.Join(filepath.Dir(exe), "update.ps1")):
		return "task"
	}
	return ""
}

func inDocker() bool { return exists("/.dockerenv") }

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// errRestart: exit, to be started again with the new version (Docker).
var errRestart = errors.New("restarting for the update")

// requestUpdate: ask the updater for the version Sentry Lens hands out.
func requestUpdate(cfg Config, version string) error {
	switch updater(cfg) {
	case "restart":
		return errRestart
	case "systemd", "task":
		return os.WriteFile(filepath.Join(cfg.StateDir, requestFile),
			[]byte(version+" "+time.Now().UTC().Format(time.RFC3339)+"\n"), 0o600)
	}
	return errors.New("no updater: run the install line again (2.5.0+ installers add one)")
}
