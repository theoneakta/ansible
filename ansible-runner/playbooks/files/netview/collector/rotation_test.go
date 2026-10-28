package main

import (
	"os"
	"path/filepath"
	"testing"
)

// A token Sentry Lens made (Python's cryptography.fernet, as snmp.collector_fernet
// does) for a collector with oldKey - the collector must open it.
const (
	oldKey  = "slc_test_old_key_0123456789abcdefghij"
	newKey  = "slc_test_new_key_9876543210zyxwvutsrqpo"
	pyToken = "gAAAAABq3trD31iINHF2dhb6NQPyGrYAhIGb7bTb-jjdAtPLekVlhrWZyMUG0n07mx60EdVPAMUXHUpJ37fKqDl-7lnjyyGut_-MPKRA56zUQqe3W3ERBqaZ0IX3NQQL7Cn1F2y9x10f"
)

func TestFernetFromPython(t *testing.T) {
	got, err := fernetOpen(oldKey, pyToken)
	if err != nil || string(got) != newKey {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := fernetOpen(newKey, pyToken); err == nil {
		t.Fatal("opened with the wrong key")
	}
}

func TestRotatedKeyKeptAndReinstallWins(t *testing.T) {
	dir := t.TempDir()
	if k := stateKey(dir, oldKey); k != "" {
		t.Fatalf("no state yet, got %q", k)
	}
	if err := saveKey(dir, oldKey, newKey); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(filepath.Join(dir, "key.json")); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode().Perm())
	}
	if k := stateKey(dir, oldKey); k != newKey { // restarted, same install: the rotated key
		t.Fatalf("got %q", k)
	}
	if k := stateKey(dir, "slc_reinstalled_with_a_fresh_key_0000000"); k != "" { // reinstalled: the configured key
		t.Fatalf("got %q", k)
	}
	if _, err := os.Stat(filepath.Join(dir, "key.json")); !os.IsNotExist(err) {
		t.Fatal("the stale rotated key should be gone")
	}
}
