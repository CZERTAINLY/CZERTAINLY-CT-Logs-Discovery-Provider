package health

import (
	"CZERTAINLY-CT-Logs-Discovery-Provider/internal/model"
	"context"
	"net/http"
)

// HealthCheckAPIService is a service that implements the logic for the HealthCheckAPIServicer
// This service should implement the business logic for every endpoint for the HealthCheckAPI API.
// Include any external packages or services that will be required by this service.
type HealthCheckAPIService struct {
}

// NewHealthCheckAPIService creates a default api service
func NewHealthCheckAPIService() HealthCheckAPIServicer {
	return &HealthCheckAPIService{}
}

// CheckHealth - Health check
func (s *HealthCheckAPIService) CheckHealth(ctx context.Context) (model.ImplResponse, error) {
	return model.Response(http.StatusOK, model.HealthDto{
		Status: model.OK,
	}), nil
}
