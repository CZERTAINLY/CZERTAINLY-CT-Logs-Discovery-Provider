package discovery

import (
	"CZERTAINLY-CT-Logs-Discovery-Provider/internal/db"
	"CZERTAINLY-CT-Logs-Discovery-Provider/internal/model"
	"CZERTAINLY-CT-Logs-Discovery-Provider/internal/sslmate"
	"CZERTAINLY-CT-Logs-Discovery-Provider/internal/utils"
	"context"
	"github.com/yuseferi/zax/v2"
	"go.uber.org/zap"
	"net/http"
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
		Status:       string(response.Status),
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

	err := s.discoveryRepo.CreateDiscovery(discovery)
	if err != nil {
		return model.Response(http.StatusNotFound, model.ErrorMessageDto{Message: "Unable to create discovery " + discovery.UUID}), nil
	}

	s.log.With(zax.Get(ctx)...).Info("Starting discovery of certificates", zap.String("discovery_uuid", discovery.UUID))
	go s.DiscoveryCertificates(ctx, discovery, domainData, apiKeyData)

	return model.Response(http.StatusOK, response), nil
}

// GetDiscovery - Get Discovery status and result
func (s *DiscoveryAPIService) GetDiscovery(ctx context.Context, uuid string, discoveryDataRequestDto model.DiscoveryDataRequestDto) (model.ImplResponse, error) {
	discovery, err := s.discoveryRepo.FindDiscoveryByUUID(uuid)
	if err != nil {
		return model.Response(http.StatusNotFound, model.ErrorMessageDto{Message: "Discovery " + uuid + " not found."}), nil
	}
	if discovery.Status == "IN_PROGRESS" {
		return model.Response(http.StatusOK, model.DiscoveryProviderDto{Uuid: discovery.UUID, Name: discovery.Name, Status: model.IN_PROGRESS, TotalCertificatesDiscovered: 0, CertificateData: nil, Meta: nil}), nil
	} else {
		pagination := db.Pagination{
			Page:  int(discoveryDataRequestDto.PageNumber),
			Limit: int(discoveryDataRequestDto.ItemsPerPage),
		}
		result, _ := s.discoveryRepo.List(pagination, discovery)
		var certificateDtos []model.DiscoveryProviderCertificateDataDto
		rows, _ := result.Rows.([]*db.Certificate)
		for _, certificateData := range rows {
			discoveryProviderCertificateDataDto := model.DiscoveryProviderCertificateDataDto{
				Uuid:          certificateData.UUID,
				Base64Content: certificateData.Base64Content,
			}
			certificateDtos = append(certificateDtos, discoveryProviderCertificateDataDto)
		}

		return model.Response(http.StatusOK, model.DiscoveryProviderDto{Uuid: discovery.UUID, Name: discovery.Name, Status: model.COMPLETED, TotalCertificatesDiscovered: result.TotalRows, CertificateData: certificateDtos, Meta: nil}), nil
	}

}

func (s *DiscoveryAPIService) DiscoveryCertificates(ctx context.Context, discovery *db.Discovery, domain string, apiKey string) {
	// get the client
	clientConfig := sslmate.NewConfiguration()
	clientConfig.UserAgent = "CZERTAINLY-CT-Logs-Discovery-Provider"
	clientConfig.Servers = sslmate.ServerConfigurations{
		{URL: "https://api.certspotter.com"},
	}
	client := sslmate.NewAPIClient(clientConfig)

	response, _, err := client.CTSearchV1APIService.GetIssuances(ctx, domain, apiKey).Execute()

	if err != nil {
		s.log.With(zax.Get(ctx)...).Error(err.Error())
		discovery.Status = "FAILED"
		err := s.discoveryRepo.UpdateDiscovery(discovery)
		if err != nil {
			s.log.With(zax.Get(ctx)...).Error(err.Error())
		}
		return
	}

	if response != nil {
		var certificateKeys []*db.Certificate
		for _, issuance := range *response {
			certDer := issuance.GetCertDer()
			s.log.With(zax.Get(ctx)...).Debug("Issuance ID: %s, CertDer: %s", zap.String("id", issuance.GetId()), zap.String("cert_der", certDer))
			certificate := db.Certificate{
				UUID:          utils.DeterministicGUID(certDer),
				Base64Content: certDer,
			}
			certificateKeys = append(certificateKeys, &certificate)
		}
		err = s.discoveryRepo.AssociateCertificatesToDiscovery(discovery, certificateKeys...)
		if err != nil {
			discovery.Status = "FAILED"
			s.log.With(zax.Get(ctx)...).Error(err.Error())
			err := s.discoveryRepo.UpdateDiscovery(discovery)
			if err != nil {
				s.log.With(zax.Get(ctx)...).Error(err.Error())
			}
			return
		}
	} else {
		s.log.With(zax.Get(ctx)...).Info("No issuance objects found.")
	}

	// Update discovery status to "COMPLETED"
	discovery.Status = "COMPLETED"
	err = s.discoveryRepo.UpdateDiscovery(discovery)
	if err != nil {
		discovery.Status = "FAILED"
		s.log.With(zax.Get(ctx)...).Error(err.Error())
		err := s.discoveryRepo.UpdateDiscovery(discovery)
		if err != nil {
			s.log.With(zax.Get(ctx)...).Error(err.Error())
		}
		return
	}

	s.log.With(zax.Get(ctx)...).Info("Discovery completed", zap.String("discovery_uuid", discovery.UUID), zap.Int("total_certificates", len(discovery.Certificates)))
}
