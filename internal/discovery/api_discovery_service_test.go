package discovery

import "testing"

// setMandatoryDatabaseEnv sets the variables config.Get treats as required, so
// a test can read the SSLMate settings without tripping its fatal exit.
func setMandatoryDatabaseEnv(t *testing.T) {
	t.Helper()
	t.Setenv("DATABASE_USER", "user")
	t.Setenv("DATABASE_PASSWORD", "password")
	t.Setenv("DATABASE_NAME", "ctlogs")
}

func TestNewSSLMateClientIdentifiesTheConnector(t *testing.T) {
	setMandatoryDatabaseEnv(t)
	t.Setenv("SSLMATE_BASE_URL", "https://sslmate.example.com")

	got := newSSLMateClient().GetConfig().UserAgent

	if got != "ILM-CT-Logs-Discovery-Provider" {
		t.Errorf("user agent: got %q, want %q", got, "ILM-CT-Logs-Discovery-Provider")
	}
}

func TestNewSSLMateClientUsesTheConfiguredBaseURL(t *testing.T) {
	setMandatoryDatabaseEnv(t)
	t.Setenv("SSLMATE_BASE_URL", "https://sslmate.example.com")

	got, err := newSSLMateClient().GetConfig().ServerURL(0, nil)
	if err != nil {
		t.Fatalf("resolve server URL: %v", err)
	}
	if got != "https://sslmate.example.com" {
		t.Errorf("server URL: got %q, want %q", got, "https://sslmate.example.com")
	}
}

func TestNewSSLMateClientFallsBackToTheDefaultBaseURL(t *testing.T) {
	setMandatoryDatabaseEnv(t)
	t.Setenv("SSLMATE_BASE_URL", "")

	got, err := newSSLMateClient().GetConfig().ServerURL(0, nil)
	if err != nil {
		t.Fatalf("resolve server URL: %v", err)
	}
	if got != "https://api.certspotter.com" {
		t.Errorf("server URL: got %q, want %q", got, "https://api.certspotter.com")
	}
}
