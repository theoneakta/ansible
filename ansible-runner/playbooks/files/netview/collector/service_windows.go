//go:build windows

package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "SentryLensCollector"

type service struct{ cfgPath string }

func (s service) Execute(args []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	cfg, err := loadConfig(s.cfgPath)
	if err != nil {
		return true, 1
	}
	if cfg.LogFile == "" {
		cfg.LogFile = filepath.Join(filepath.Dir(s.cfgPath), "collector.log")
	}
	setupLog(cfg.LogFile)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() { loop(cfg, stop); close(done) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for c := range req {
		switch c.Cmd {
		case svc.Interrogate:
			status <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			status <- svc.Status{State: svc.StopPending}
			close(stop)
			select {
			case <-done:
			case <-time.After(10 * time.Second):
			}
			return false, 0
		}
	}
	return false, 0
}

// runAsService: true when the service manager started us (it then runs until stopped).
func runAsService(cfgPath string) bool {
	is, err := svc.IsWindowsService()
	if err != nil || !is {
		return false
	}
	if err := svc.Run(serviceName, service{cfgPath}); err != nil {
		log.Printf("service: %v", err)
	}
	return true
}

// serviceCommand: install (with its config file) or uninstall the service.
func serviceCommand(cmd, cfgPath string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("the service manager (run as administrator): %w", err)
	}
	defer m.Disconnect()
	if cmd == "uninstall" {
		s, err := m.OpenService(serviceName)
		if err != nil {
			return nil // not installed
		}
		defer s.Close()
		_, _ = s.Control(svc.Stop)
		time.Sleep(2 * time.Second)
		return s.Delete()
	}
	if cfgPath == "" {
		return fmt.Errorf("install --config <file with SENTRY_URL and SENTRY_KEY>")
	}
	if _, err := loadConfig(cfgPath); err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if s, err := m.OpenService(serviceName); err == nil { // already there: replace it
		_, _ = s.Control(svc.Stop)
		time.Sleep(2 * time.Second)
		_ = s.Delete()
		s.Close()
		time.Sleep(time.Second)
	}
	// LocalService: no administrator rights - SendARP, IcmpSendEcho and TCP need none.
	s, err := m.CreateService(serviceName, exe, mgr.Config{DisplayName: "Sentry Lens collector", StartType: mgr.StartAutomatic,
		Description: "Discovers the network's devices and reads them over SNMP for Sentry Lens.",
		ServiceStartName: `NT AUTHORITY\LocalService`}, "run", "--config", cfgPath)
	if err != nil {
		return err
	}
	defer s.Close()
	_ = s.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
		{Type: mgr.ServiceRestart, Delay: time.Minute}, {Type: mgr.ServiceRestart, Delay: 5 * time.Minute}}, 86400)
	return s.Start()
}
