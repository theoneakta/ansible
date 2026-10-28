//go:build !windows

package main

import "fmt"

// On Linux the installer (Sentry Lens: /collector/install.sh) makes a systemd service.
func runAsService(string) bool { return false }

func serviceCommand(cmd, _ string) error {
	return fmt.Errorf("%s: Windows only - on Linux use the install script (Sentry Lens > Assets > Collectors)", cmd)
}
