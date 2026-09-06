package utils

import "testing"

func TestDeterministicGUIDIsStableAcrossCalls(t *testing.T) {
	first := DeterministicGUID("ct-logs", "example.com")
	second := DeterministicGUID("ct-logs", "example.com")
	if first != second {
		t.Fatalf("same input produced different GUIDs: %q and %q", first, second)
	}
}

func TestDeterministicGUIDSeparatesDifferentInputs(t *testing.T) {
	if DeterministicGUID("a", "b") == DeterministicGUID("b", "a") {
		t.Fatal("argument order must change the GUID")
	}
}

func TestDeterministicGUIDIsAWellFormedUUID(t *testing.T) {
	got := DeterministicGUID("ct-logs", "example.com")
	if len(got) != 36 {
		t.Fatalf("got %q (%d chars), want a 36-character UUID", got, len(got))
	}
}

func TestGenerateRandomUUIDProducesDistinctValues(t *testing.T) {
	first := GenerateRandomUUID()
	second := GenerateRandomUUID()
	if first == second {
		t.Fatal("two calls returned the same UUID")
	}
}
