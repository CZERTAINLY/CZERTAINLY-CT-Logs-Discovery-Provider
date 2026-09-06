package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/OmniTrustILM/ct-logs-discovery-provider/internal/db"
	"github.com/OmniTrustILM/ct-logs-discovery-provider/internal/model"
	"github.com/OmniTrustILM/ct-logs-discovery-provider/internal/sslmate"
	"go.uber.org/zap"
)

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

	if got != "CT-Logs-Discovery-Provider" {
		t.Errorf("user agent: got %q, want %q", got, "CT-Logs-Discovery-Provider")
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

// fakeAssociateCall records one call to
// fakeDiscoveryRepository.AssociateCertificatesToDiscovery.
type fakeAssociateCall struct {
	discovery    db.Discovery
	certificates []*db.Certificate
}

// fakeDiscoveryRepository is an in-memory stand-in for *db.DiscoveryRepository
// satisfying the discoveryRepository interface. It records the calls
// DiscoveryCertificates makes and returns canned errors, so tests can drive
// every branch of that method without a live database.
type fakeDiscoveryRepository struct {
	findDiscovery *db.Discovery

	updateDiscoveryCalls []db.Discovery
	updateDiscoveryErr   error

	associateCalls []fakeAssociateCall
	associateErr   error
}

func (f *fakeDiscoveryRepository) FindDiscoveryByUUID(uuid string) (*db.Discovery, error) {
	if f.findDiscovery != nil {
		return f.findDiscovery, nil
	}
	return nil, errors.New("fakeDiscoveryRepository: FindDiscoveryByUUID not configured for this test")
}

func (f *fakeDiscoveryRepository) DeleteDiscovery(discovery *db.Discovery) error {
	return errors.New("fakeDiscoveryRepository: DeleteDiscovery not configured for this test")
}

func (f *fakeDiscoveryRepository) CreateDiscovery(discovery *db.Discovery) error {
	return errors.New("fakeDiscoveryRepository: CreateDiscovery not configured for this test")
}

func (f *fakeDiscoveryRepository) List(pagination db.Pagination, discovery *db.Discovery) (*db.Pagination, error) {
	return nil, errors.New("fakeDiscoveryRepository: List not configured for this test")
}

func (f *fakeDiscoveryRepository) UpdateDiscovery(discovery *db.Discovery) error {
	f.updateDiscoveryCalls = append(f.updateDiscoveryCalls, *discovery)
	return f.updateDiscoveryErr
}

func (f *fakeDiscoveryRepository) AssociateCertificatesToDiscovery(discovery *db.Discovery, certificates ...*db.Certificate) error {
	f.associateCalls = append(f.associateCalls, fakeAssociateCall{discovery: *discovery, certificates: certificates})
	return f.associateErr
}

// newIssuancesServer starts an httptest server playing the role of the
// SSLMate CT search API used by DiscoveryCertificates. It answers the first
// request with issuances and every request after that with an empty page, so
// the discovery loop stops paginating. It always succeeds on the first
// attempt so the retry loop in DiscoveryCertificates - a 15 second base delay
// - never engages; a test relying on that retry path would hang for minutes.
func newIssuancesServer(t *testing.T, issuances []sslmate.IssuanceObject) *httptest.Server {
	t.Helper()

	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		page := issuances
		if calls.Add(1) > 1 {
			page = []sslmate.IssuanceObject{}
		}
		if err := json.NewEncoder(w).Encode(page); err != nil {
			t.Errorf("encode issuances response: %v", err)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func TestDiscoveryCertificatesCompletesWhenNoIssuancesAreFound(t *testing.T) {
	setMandatoryDatabaseEnv(t)
	server := newIssuancesServer(t, nil)
	t.Setenv("SSLMATE_BASE_URL", server.URL)

	repo := &fakeDiscoveryRepository{}
	svc := &DiscoveryAPIService{discoveryRepo: repo, log: zap.NewNop()}
	target := &db.Discovery{UUID: "discovery-uuid", Name: "example.com"}

	svc.DiscoveryCertificates(context.Background(), target, "example.com", "", false, false, time.Now().Add(-time.Hour), time.Now())

	if target.Status != model.COMPLETED {
		t.Fatalf("status: got %q, want %q", target.Status, model.COMPLETED)
	}
	if len(repo.associateCalls) != 0 {
		t.Errorf("AssociateCertificatesToDiscovery calls: got %d, want 0", len(repo.associateCalls))
	}
	if len(repo.updateDiscoveryCalls) != 1 {
		t.Fatalf("UpdateDiscovery calls: got %d, want 1", len(repo.updateDiscoveryCalls))
	}
	if got := repo.updateDiscoveryCalls[0].Status; got != model.COMPLETED {
		t.Errorf("updated status: got %q, want %q", got, model.COMPLETED)
	}
}

func TestDiscoveryCertificatesAssociatesDiscoveredCertificates(t *testing.T) {
	setMandatoryDatabaseEnv(t)
	issuance := sslmate.IssuanceObject{
		Id:      "issuance-1",
		CertDer: "certificate-der-bytes",
		Issuer:  sslmate.IssuerObject{FriendlyName: "Example CA"},
	}
	server := newIssuancesServer(t, []sslmate.IssuanceObject{issuance})
	t.Setenv("SSLMATE_BASE_URL", server.URL)

	repo := &fakeDiscoveryRepository{}
	svc := &DiscoveryAPIService{discoveryRepo: repo, log: zap.NewNop()}
	target := &db.Discovery{UUID: "discovery-uuid", Name: "example.com"}

	svc.DiscoveryCertificates(context.Background(), target, "example.com", "", false, false, time.Now().Add(-time.Hour), time.Now())

	if target.Status != model.COMPLETED {
		t.Fatalf("status: got %q, want %q", target.Status, model.COMPLETED)
	}
	if len(repo.associateCalls) != 1 {
		t.Fatalf("AssociateCertificatesToDiscovery calls: got %d, want 1", len(repo.associateCalls))
	}
	certs := repo.associateCalls[0].certificates
	if len(certs) != 1 {
		t.Fatalf("certificates in call: got %d, want 1", len(certs))
	}
	if certs[0].Base64Content != issuance.CertDer {
		t.Errorf("certificate content: got %q, want %q", certs[0].Base64Content, issuance.CertDer)
	}
	if certs[0].UUID == "" {
		t.Error("certificate UUID: got empty string, want a deterministic UUID")
	}
}

func TestDiscoveryCertificatesFailsWhenAssociationErrors(t *testing.T) {
	setMandatoryDatabaseEnv(t)
	issuance := sslmate.IssuanceObject{
		Id:      "issuance-1",
		CertDer: "certificate-der-bytes",
		Issuer:  sslmate.IssuerObject{FriendlyName: "Example CA"},
	}
	server := newIssuancesServer(t, []sslmate.IssuanceObject{issuance})
	t.Setenv("SSLMATE_BASE_URL", server.URL)

	repo := &fakeDiscoveryRepository{associateErr: errors.New("association failed")}
	svc := &DiscoveryAPIService{discoveryRepo: repo, log: zap.NewNop()}
	target := &db.Discovery{UUID: "discovery-uuid", Name: "example.com"}

	svc.DiscoveryCertificates(context.Background(), target, "example.com", "", false, false, time.Now().Add(-time.Hour), time.Now())

	if target.Status != model.FAILED {
		t.Fatalf("status: got %q, want %q", target.Status, model.FAILED)
	}
	if len(target.Meta) == 0 {
		t.Error("expected failure metadata to be recorded on the discovery")
	}
	if len(repo.updateDiscoveryCalls) != 1 {
		t.Fatalf("UpdateDiscovery calls: got %d, want 1", len(repo.updateDiscoveryCalls))
	}
	if got := repo.updateDiscoveryCalls[0].Status; got != model.FAILED {
		t.Errorf("updated status: got %q, want %q", got, model.FAILED)
	}
}

func TestFailDiscoveryRecordsTheReasonAndPersistsIt(t *testing.T) {
	repo := &fakeDiscoveryRepository{}
	svc := &DiscoveryAPIService{discoveryRepo: repo, log: zap.NewNop()}
	target := &db.Discovery{UUID: "discovery-uuid", Name: "example.com"}

	svc.failDiscovery(context.Background(), target, "the upstream API rejected the request")

	if target.Status != model.FAILED {
		t.Fatalf("status: got %q, want %q", target.Status, model.FAILED)
	}
	if !strings.Contains(string(target.Meta), "the upstream API rejected the request") {
		t.Errorf("expected the reason in the metadata, got %q", string(target.Meta))
	}
	if len(repo.updateDiscoveryCalls) != 1 {
		t.Fatalf("UpdateDiscovery calls: got %d, want 1", len(repo.updateDiscoveryCalls))
	}
	if got := repo.updateDiscoveryCalls[0].Status; got != model.FAILED {
		t.Errorf("persisted status: got %q, want %q", got, model.FAILED)
	}
}

func TestFailDiscoveryStillMarksTheDiscoveryWhenPersistingFails(t *testing.T) {
	repo := &fakeDiscoveryRepository{updateDiscoveryErr: errors.New("database unavailable")}
	svc := &DiscoveryAPIService{discoveryRepo: repo, log: zap.NewNop()}
	target := &db.Discovery{UUID: "discovery-uuid", Name: "example.com"}

	svc.failDiscovery(context.Background(), target, "discovery failed")

	if target.Status != model.FAILED {
		t.Errorf("status: got %q, want %q", target.Status, model.FAILED)
	}
	if len(repo.updateDiscoveryCalls) != 1 {
		t.Errorf("UpdateDiscovery calls: got %d, want 1", len(repo.updateDiscoveryCalls))
	}
}

func TestListAttributeDefinitionsRejectsAnUnknownKind(t *testing.T) {
	svc := &ConnectorAttributesAPIService{log: zap.NewNop()}

	response, err := svc.ListAttributeDefinitions(context.Background(), "not-a-kind")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if response.Code != http.StatusUnprocessableEntity {
		t.Errorf("code: got %d, want %d", response.Code, http.StatusUnprocessableEntity)
	}
}

func TestValidateAttributesRejectsAnUnknownKind(t *testing.T) {
	svc := &ConnectorAttributesAPIService{log: zap.NewNop()}

	response, err := svc.ValidateAttributes(context.Background(), "not-a-kind", nil)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if response.Code != http.StatusUnprocessableEntity {
		t.Errorf("code: got %d, want %d", response.Code, http.StatusUnprocessableEntity)
	}
}

func TestDeleteDiscoveryReportsAFailedDelete(t *testing.T) {
	repo := &fakeDiscoveryRepository{findDiscovery: &db.Discovery{UUID: "discovery-uuid"}}
	svc := &DiscoveryAPIService{discoveryRepo: repo, log: zap.NewNop()}

	response, err := svc.DeleteDiscovery(context.Background(), "discovery-uuid")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if response.Code != http.StatusInternalServerError {
		t.Errorf("code: got %d, want %d", response.Code, http.StatusInternalServerError)
	}
}

func TestDiscoveryCertificatesFailsWhenTheCompletionUpdateFails(t *testing.T) {
	setMandatoryDatabaseEnv(t)
	server := newIssuancesServer(t, nil)
	t.Setenv("SSLMATE_BASE_URL", server.URL)

	repo := &fakeDiscoveryRepository{updateDiscoveryErr: errors.New("database unavailable")}
	svc := &DiscoveryAPIService{discoveryRepo: repo, log: zap.NewNop()}
	target := &db.Discovery{UUID: "discovery-uuid", Name: "example.com"}

	svc.DiscoveryCertificates(context.Background(), target, "example.com", "", false, false, time.Now().Add(-time.Hour), time.Now())

	if target.Status != model.FAILED {
		t.Errorf("status: got %q, want %q", target.Status, model.FAILED)
	}
}

func TestDiscoverCertificateToleratesAnEmptyDomainAndForeignCredential(t *testing.T) {
	setMandatoryDatabaseEnv(t)
	repo := &fakeDiscoveryRepository{}
	svc := &DiscoveryAPIService{discoveryRepo: repo, log: zap.NewNop()}

	request := model.DiscoveryRequestDto{
		Name: "example-discovery",
		Attributes: []model.Attribute{
			model.DataAttribute{
				Uuid:    model.DISCOVERY_DATA_ATTRIBUTE_DOMAIN_UUID,
				Content: []model.AttributeContent{nil},
			},
			model.DataAttribute{
				Uuid: model.DISCOVERY_DATA_ATTRIBUTE_API_KEY_UUID,
				Content: []model.AttributeContent{
					model.CredentialAttributeContent{
						Data: model.CredentialAttributeContentData{Kind: "Basic"},
					},
				},
			},
		},
	}

	// CreateDiscovery is unconfigured on the fake and therefore fails, so the
	// request is rejected before any discovery goroutine is started.
	response, err := svc.DiscoverCertificate(context.Background(), request)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if response.Code != http.StatusNotFound {
		t.Errorf("code: got %d, want %d", response.Code, http.StatusNotFound)
	}
}
