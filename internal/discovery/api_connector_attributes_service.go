package discovery

import (
	"CZERTAINLY-CT-Logs-Discovery-Provider/internal/model"
	"context"
	"fmt"
	"github.com/yuseferi/zax/v2"
	"net/http"
	"strings"

	"go.uber.org/zap"
)

// ConnectorAttributesAPIService is a service that implements the logic for the ConnectorAttributesAPIServicer
// This service should implement the business logic for every endpoint for the ConnectorAttributesAPI API.
// Include any external packages or services that will be required by this service.
type ConnectorAttributesAPIService struct {
	log *zap.Logger
}

// NewConnectorAttributesAPIService creates a default api service
func NewConnectorAttributesAPIService(logger *zap.Logger) ConnectorAttributesAPIServicer {
	return &ConnectorAttributesAPIService{
		log: logger,
	}
}

// ListAttributeDefinitions - List available Attributes
func (s *ConnectorAttributesAPIService) ListAttributeDefinitions(ctx context.Context, kind string) (model.ImplResponse, error) {
	if !strings.EqualFold(kind, model.CONNECTOR_KIND) {
		message := fmt.Sprintf("Unrecognized kind: %s", kind)
		s.log.With(zax.Get(ctx)...).Info(message)
		return model.Response(http.StatusUnprocessableEntity, message), nil
	}

	var attributes []model.Attribute
	infoAttribute := model.GetAttributeDefByUUID(model.DISCOVERY_INFO_ATTRIBUTE_OVERVIEW_UUID).(model.InfoAttribute)
	attributes = append(attributes, infoAttribute)
	dataAttribute := model.GetAttributeDefByUUID(model.DISCOVERY_DATA_ATTRIBUTE_API_KEY_UUID).(model.DataAttribute)
	attributes = append(attributes, dataAttribute)
	dataAttribute = model.GetAttributeDefByUUID(model.DISCOVERY_DATA_ATTRIBUTE_DOMAIN_UUID).(model.DataAttribute)
	attributes = append(attributes, dataAttribute)
	return model.Response(http.StatusOK, attributes), nil

}

// ValidateAttributes - Validate Attributes
func (s *ConnectorAttributesAPIService) ValidateAttributes(ctx context.Context, kind string, requestAttributeDto []model.Attribute) (model.ImplResponse, error) {
	if !strings.EqualFold(kind, model.CONNECTOR_KIND) {
		message := fmt.Sprintf("Unrecognized kind: %s", kind)
		s.log.With(zax.Get(ctx)...).Info(message)
		return model.Response(http.StatusUnprocessableEntity, message), nil
	}

	domain := model.GetAttributeFromArrayByUUID(model.DISCOVERY_DATA_ATTRIBUTE_DOMAIN_UUID, requestAttributeDto).(model.DataAttribute)
	// if domain is empty return error
	if domain.GetContent()[0] == nil {
		return model.Response(422, []string{"Domain attribute not found"}), nil
	}

	return model.Response(http.StatusOK, nil), nil
}
