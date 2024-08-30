package discovery

import (
	"CZERTAINLY-CT-Logs-Discovery-Provider/internal/config"
	"CZERTAINLY-CT-Logs-Discovery-Provider/internal/db"
	"CZERTAINLY-CT-Logs-Discovery-Provider/internal/model"
	"CZERTAINLY-CT-Logs-Discovery-Provider/internal/sslmate"
	"CZERTAINLY-CT-Logs-Discovery-Provider/internal/utils"
	"context"
	"encoding/json"
	"github.com/yuseferi/zax/v2"
	"go.uber.org/zap"
	"math/rand"
	"net/http"
	"strconv"
	"time"
)

// DiscoveryAPIService is a service that implements the logic for the DiscoveryAPIServicer
// This service should implement the business logic for every endpoint for the DiscoveryAPI API.
// Include any external packages or services that will be required by this service.
type DiscoveryAPIService struct {
	discoveryRepo *db.DiscoveryRepository
	log           *zap.Logger
}

// NewDiscoveryAPIService creates a default api service
func NewDiscoveryAPIService(discoveryRepo *db.DiscoveryRepository, logger *zap.Logger) DiscoveryAPIServicer {
	return &DiscoveryAPIService{
		discoveryRepo: discoveryRepo,
		log:           logger,
	}
}

// DeleteDiscovery - Delete Discovery
func (s *DiscoveryAPIService) DeleteDiscovery(ctx context.Context, uuid string) (model.ImplResponse, error) {
	discovery, err := s.discoveryRepo.FindDiscoveryByUUID(uuid)
	if err != nil {
		return model.Response(http.StatusNotFound, model.ErrorMessageDto{Message: "Discovery " + uuid + " not found."}), nil
	}

	s.log.With(zax.Get(ctx)...).Info("Deleting discovery", zap.String("discovery_uuid", discovery.UUID))
	err = s.discoveryRepo.DeleteDiscovery(discovery)
	if err != nil {
		return model.Response(http.StatusInternalServerError, model.ErrorMessageDto{Message: "Unable to delete discover" + discovery.UUID}), nil
	}

	return model.Response(204, nil), nil
}

// DiscoverCertificate - Initiate certificate Discovery
func (s *DiscoveryAPIService) DiscoverCertificate(ctx context.Context, discoveryRequestDto model.DiscoveryRequestDto) (model.ImplResponse, error) {
	response := model.DiscoveryProviderDto{
		Uuid:                        utils.DeterministicGUID(discoveryRequestDto.Name),
		Name:                        discoveryRequestDto.Name,
		Status:                      model.IN_PROGRESS,
		TotalCertificatesDiscovered: 0,
		CertificateData:             nil,
		Meta:                        nil,
	}
	discovery := &db.Discovery{
		UUID:         response.Uuid,
		Name:         response.Name,
		Status:       response.Status,
		Meta:         nil,
		Certificates: nil,
	}

	domainData := ""
	domain := model.GetAttributeFromArrayByUUID(model.DISCOVERY_DATA_ATTRIBUTE_DOMAIN_UUID, discoveryRequestDto.Attributes).(model.DataAttribute)
	if domain.GetContent()[0] == nil {
		s.log.With(zax.Get(ctx)...).Info("Domain attribute not found")
	} else {
		domainData = domain.GetContent()[0].GetData().(string)
	}

	apiKeyData := ""
	if model.GetAttributeFromArrayByUUID(model.DISCOVERY_DATA_ATTRIBUTE_API_KEY_UUID, discoveryRequestDto.Attributes) != nil {
		apiKey := model.GetAttributeFromArrayByUUID(model.DISCOVERY_DATA_ATTRIBUTE_API_KEY_UUID, discoveryRequestDto.Attributes).(model.DataAttribute)
		if apiKey.GetContent()[0].(model.CredentialAttributeContent).GetData().(model.CredentialAttributeContentData).Kind != "ApiKey" {
			s.log.With(zax.Get(ctx)...).Info("Incompatible credential type, ApiKey expected", zap.String("kind", apiKey.GetContent()[0].(model.CredentialAttributeContent).GetData().(model.CredentialAttributeContentData).Kind))
		} else {
			apiKeyData = model.GetApiKeyFromAttribute(apiKey)
		}
	}

	includeSubdomains := false
	if model.GetAttributeFromArrayByUUID(model.DISCOVERY_DATA_ATTRIBUTE_INCLUDE_SUBDOMAINS_UUID, discoveryRequestDto.Attributes) != nil {
		includeSubdomainsAttribute := model.GetAttributeFromArrayByUUID(model.DISCOVERY_DATA_ATTRIBUTE_INCLUDE_SUBDOMAINS_UUID, discoveryRequestDto.Attributes).(model.DataAttribute)
		includeSubdomains = includeSubdomainsAttribute.GetContent()[0].GetData().(bool)
	}

	matchWildcards := false
	if model.GetAttributeFromArrayByUUID(model.DISCOVERY_DATA_ATTRIBUTE_MATCH_WILDCARDS_UUID, discoveryRequestDto.Attributes) != nil {
		matchWildcardsAttribute := model.GetAttributeFromArrayByUUID(model.DISCOVERY_DATA_ATTRIBUTE_MATCH_WILDCARDS_UUID, discoveryRequestDto.Attributes).(model.DataAttribute)
		matchWildcards = matchWildcardsAttribute.GetContent()[0].GetData().(bool)
	}

	discoveredFrom, err := time.Parse(time.RFC3339, "2013-01-01T00:00:00Z")
	if err != nil {
		return model.Response(http.StatusInternalServerError, model.ErrorMessageDto{Message: "Unable to parse discoveredFrom date " + err.Error()}), nil
	}
	if model.GetAttributeFromArrayByUUID(model.DISCOVERY_DATA_ATTRIBUTE_AFTER_UUID, discoveryRequestDto.Attributes) != nil {
		afterAttribute := model.GetAttributeFromArrayByUUID(model.DISCOVERY_DATA_ATTRIBUTE_AFTER_UUID, discoveryRequestDto.Attributes).(model.DataAttribute)
		discoveredFrom = afterAttribute.GetContent()[0].GetData().(time.Time)
	}

	// Must be at least 15 minutes before the current time
	discoveredBefore := time.Now().Add(-15 * time.Minute)
	if model.GetAttributeFromArrayByUUID(model.DISCOVERY_DATA_ATTRIBUTE_BEFORE_UUID, discoveryRequestDto.Attributes) != nil {
		beforeAttribute := model.GetAttributeFromArrayByUUID(model.DISCOVERY_DATA_ATTRIBUTE_BEFORE_UUID, discoveryRequestDto.Attributes).(model.DataAttribute)
		discoveredBefore = beforeAttribute.GetContent()[0].GetData().(time.Time)
	}

	err = s.discoveryRepo.CreateDiscovery(discovery)
	if err != nil {
		return model.Response(http.StatusNotFound, model.ErrorMessageDto{Message: "Unable to create discovery " + discovery.UUID + ", " + err.Error()}), nil
	}

	s.log.With(zax.Get(ctx)...).Info("Starting discovery of certificates", zap.String("discovery_uuid", discovery.UUID), zap.String("discovery_name", discovery.Name))
	go s.DiscoveryCertificates(ctx, discovery, domainData, apiKeyData, includeSubdomains, matchWildcards, discoveredFrom, discoveredBefore)

	return model.Response(http.StatusOK, response), nil
}

// GetDiscovery - Get Discovery status and result
func (s *DiscoveryAPIService) GetDiscovery(ctx context.Context, uuid string, discoveryDataRequestDto model.DiscoveryDataRequestDto) (model.ImplResponse, error) {
	discovery, err := s.discoveryRepo.FindDiscoveryByUUID(uuid)
	if err != nil {
		return model.Response(http.StatusNotFound, model.ErrorMessageDto{Message: "Discovery " + uuid + " not found."}), nil
	}
	if discovery.Status == model.IN_PROGRESS {
		return model.Response(http.StatusOK, model.DiscoveryProviderDto{Uuid: discovery.UUID, Name: discovery.Name, Status: model.IN_PROGRESS, TotalCertificatesDiscovered: 0, CertificateData: nil, Meta: nil}), nil
	}
	if discovery.Status == model.FAILED {
		metadata, err := discovery.GetMeta()
		if err != nil {
			return model.Response(http.StatusInternalServerError, model.ErrorMessageDto{Message: "Unable to get metadata for discovery " + uuid + ", " + err.Error()}), nil
		}
		return model.Response(http.StatusOK, model.DiscoveryProviderDto{Uuid: discovery.UUID, Name: discovery.Name, Status: model.FAILED, TotalCertificatesDiscovered: 0, CertificateData: nil, Meta: metadata}), nil
	} else {
		pagination := db.Pagination{
			Page:  int(discoveryDataRequestDto.PageNumber),
			Limit: int(discoveryDataRequestDto.ItemsPerPage),
		}
		result, _ := s.discoveryRepo.List(pagination, discovery)
		var certificateDtos []model.DiscoveryProviderCertificateDataDto
		rows, _ := result.Rows.([]*db.Certificate)
		for _, certificateData := range rows {
			metadata, err := certificateData.GetMeta()
			if err != nil {
				return model.Response(http.StatusInternalServerError, model.ErrorMessageDto{Message: "Unable to get metadata for certificate " + certificateData.UUID + ", " + err.Error()}), nil
			}
			discoveryProviderCertificateDataDto := model.DiscoveryProviderCertificateDataDto{
				Uuid:          certificateData.UUID,
				Base64Content: certificateData.Base64Content,
				Meta:          metadata,
			}
			certificateDtos = append(certificateDtos, discoveryProviderCertificateDataDto)
		}

		return model.Response(http.StatusOK, model.DiscoveryProviderDto{Uuid: discovery.UUID, Name: discovery.Name, Status: model.COMPLETED, TotalCertificatesDiscovered: result.TotalRows, CertificateData: certificateDtos, Meta: nil}), nil
	}

}

func (s *DiscoveryAPIService) DiscoveryCertificates(ctx context.Context, discovery *db.Discovery, domain string, apiKey string, includeSubdomains bool, matchWildcards bool, discoveredFrom time.Time, discoveredBefore time.Time) {
	// get the client
	clientConfig := sslmate.NewConfiguration()
	clientConfig.UserAgent = "CZERTAINLY-CT-Logs-Discovery-Provider"
	clientConfig.Servers = sslmate.ServerConfigurations{
		{URL: config.Get().SslMate.BaseUrl},
	}
	client := sslmate.NewAPIClient(clientConfig)

	// Define a maximum number of retries and a base delay
	const maxRetries = 5
	// 15 seconds as the base delay
	const baseDelay = 15 * time.Second

	after := ""
	for {
		var response *[]sslmate.IssuanceObject
		var err error

		// Retry loop with exponential backoff and jitter
		for attempt := 0; attempt < maxRetries; attempt++ {
			response, _, err = client.CTSearchV1APIService.GetIssuances(ctx, s.log, domain, apiKey, includeSubdomains, matchWildcards, after, discoveredFrom, discoveredBefore).Execute()

			if err == nil {
				break // exit retry loop if successful
			}

			// Log the error and prepare for the next retry
			s.log.With(zax.Get(ctx)...).Error("Attempt " + strconv.Itoa(attempt+1) + " failed: " + err.(*sslmate.GenericOpenAPIError).Model().(sslmate.ErrorObject).Message)

			// Introduce a random delay before retrying
			waitTime := baseDelay * time.Duration(1<<attempt)             // Exponential backoff
			waitTime += time.Duration(rand.Intn(1000)) * time.Millisecond // Add jitter
			// Log the wait time in seconds
			s.log.With(zax.Get(ctx)...).Info("Waiting for " + waitTime.String() + " before retrying")
			time.Sleep(waitTime)
		}

		if err != nil {
			s.log.With(zax.Get(ctx)...).Error(err.(*sslmate.GenericOpenAPIError).Model().(sslmate.ErrorObject).Message)
			discovery.Status = model.FAILED
			meta := model.CreateFailureReasonMetadataAttribute(err.(*sslmate.GenericOpenAPIError).Model().(sslmate.ErrorObject).Message)
			metaAttributes := []model.MetadataAttribute{
				meta,
			}
			err := discovery.SetMeta(metaAttributes)
			if err != nil {
				return
			}
			err = s.discoveryRepo.UpdateDiscovery(discovery)
			if err != nil {
				s.log.With(zax.Get(ctx)...).Error(err.Error())
			}
			return
		}

		if response != nil && len(*response) > 0 {
			var certificateKeys []*db.Certificate
			for _, issuance := range *response {
				certDer := issuance.GetCertDer()
				// s.log.With(zax.Get(ctx)...).Debug("Issuance ID: %s, CertDer: %s", zap.String("id", issuance.GetId()), zap.String("cert_der", certDer))
				frindlyNameMeta := model.CreateSSLMateFriendlyNameMetadataAttribute(issuance.GetIssuer().FriendlyName)
				meta := []model.MetadataAttribute{
					frindlyNameMeta,
				}
				if issuance.GetIssuer().CaaDomains != nil {
					caaDomainsMeta := model.CreateSSLMateCaaDomainsMetadataAttribute(issuance.GetIssuer().CaaDomains)
					meta = append(meta, caaDomainsMeta)
				}
				if issuance.ProblemReporting != "" {
					problemReportingMeta := model.CreateSSLMateProblemReportingMetadataAttribute(issuance.ProblemReporting)
					meta = append(meta, problemReportingMeta)
				}
				jsonMeta, _ := json.Marshal(meta)
				certificate := db.Certificate{
					UUID:          utils.DeterministicGUID(certDer),
					Base64Content: certDer,
					Meta:          jsonMeta,
				}
				certificateKeys = append(certificateKeys, &certificate)
			}
			err = s.discoveryRepo.AssociateCertificatesToDiscovery(discovery, certificateKeys...)
			if err != nil {
				discovery.Status = model.FAILED
				s.log.With(zax.Get(ctx)...).Error(err.Error())
				meta := model.CreateFailureReasonMetadataAttribute(err.Error())
				metaAttributes := []model.MetadataAttribute{
					meta,
				}
				err := discovery.SetMeta(metaAttributes)
				if err != nil {
					return
				}
				err = s.discoveryRepo.UpdateDiscovery(discovery)
				if err != nil {
					s.log.With(zax.Get(ctx)...).Error(err.Error())
				}
				return
			}
			// get the last issuance object
			lastIssuance := (*response)[len(*response)-1]
			after = lastIssuance.GetId()
		} else {
			s.log.With(zax.Get(ctx)...).Info("No additional issuance objects found.")
			break
		}
	}

	// Update discovery status to "COMPLETED"
	discovery.Status = model.COMPLETED
	err := s.discoveryRepo.UpdateDiscovery(discovery)
	if err != nil {
		discovery.Status = model.FAILED
		s.log.With(zax.Get(ctx)...).Error(err.Error())
		meta := model.CreateFailureReasonMetadataAttribute(err.Error())
		metaAttributes := []model.MetadataAttribute{
			meta,
		}
		err := discovery.SetMeta(metaAttributes)
		if err != nil {
			return
		}
		err = s.discoveryRepo.UpdateDiscovery(discovery)
		if err != nil {
			s.log.With(zax.Get(ctx)...).Error(err.Error())
		}
		return
	}

	s.log.With(zax.Get(ctx)...).Info("Discovery completed", zap.String("discovery_uuid", discovery.UUID), zap.Int("total_certificates", len(discovery.Certificates)))
}
