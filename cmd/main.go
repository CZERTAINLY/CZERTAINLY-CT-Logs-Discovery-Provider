package main

import (
	"CZERTAINLY-CT-Logs-Discovery-Provider/internal/config"
	"CZERTAINLY-CT-Logs-Discovery-Provider/internal/connectorInfo"
	"CZERTAINLY-CT-Logs-Discovery-Provider/internal/db"
	"CZERTAINLY-CT-Logs-Discovery-Provider/internal/discovery"
	"CZERTAINLY-CT-Logs-Discovery-Provider/internal/health"
	"CZERTAINLY-CT-Logs-Discovery-Provider/internal/logger"
	"CZERTAINLY-CT-Logs-Discovery-Provider/internal/model"
	"CZERTAINLY-CT-Logs-Discovery-Provider/internal/utils"
	"bytes"
	"context"
	"github.com/gorilla/mux"
	"github.com/lib/pq"
	"github.com/yuseferi/zax/v2"
	"go.uber.org/zap"
	"io"
	"net/http"
	"strings"
	"time"
)

var version = "1.0.0"

var routes map[string][]model.EndpointDto

var log = logger.Get()

func main() {
	routes = make(map[string][]model.EndpointDto)
	c := config.Get()
	log.Info("Starting CZERTAINLY-CT-Logs-Discovery-Provider", zap.String("version", version))
	conn, _ := db.ConnectDB(c)
	schema := config.Get().Database.Schema
	err := conn.Exec("CREATE SCHEMA IF NOT EXISTS " + pq.QuoteIdentifier(schema)).Error
	if err != nil {
		log.Error("Error creating schema", zap.Error(err))
	}
	db.MigrateDB(c)
	discoveryRepo, _ := db.NewDiscoveryRepository(conn)

	// Schedule the cleanup task
	go scheduleCleanup(discoveryRepo)

	DiscoveryAPIService := discovery.NewDiscoveryAPIService(discoveryRepo, log)
	DiscoveryAPIController := discovery.NewDiscoveryAPIController(DiscoveryAPIService)

	DiscoveryConnectorAttributesAPIService := discovery.NewConnectorAttributesAPIService(log)
	DiscoveryConnectorAttributesAPIController := discovery.NewConnectorAttributesAPIController(DiscoveryConnectorAttributesAPIService)

	HealthAPIService := health.NewHealthCheckAPIService()
	HealthAPIController := health.NewHealthCheckAPIController(HealthAPIService)

	topMux := http.NewServeMux()

	healthRouter := model.NewRouter(HealthAPIController)

	discoveryRouter := model.NewRouter(DiscoveryConnectorAttributesAPIController, DiscoveryAPIController)
	populateRoutes(discoveryRouter, "discoveryProvider")

	info := []model.InfoResponse{
		{
			FunctionGroupCode: "discoveryProvider",
			Kinds:             []string{model.CONNECTOR_KIND},
			EndPoints:         routes["discoveryProvider"],
		},
	}

	ConnectorInfoAPIService := connectorInfo.NewConnectorInfoAPIService(info)
	ConnectorInfoAPIController := connectorInfo.NewConnectorInfoAPIController(ConnectorInfoAPIService)
	connectorInfoRouter := model.NewRouter(ConnectorInfoAPIController)

	topMux.Handle("/v1", logMiddleware(connectorInfoRouter))
	topMux.Handle("/v1/", logMiddleware(healthRouter))
	topMux.Handle("/v1/discoveryProvider/", logMiddleware(discoveryRouter))

	err = http.ListenAndServe(":"+c.Server.Port, topMux)
	if err != nil {
		log.Fatal(err.Error())
	}
}

func logMiddleware(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// retrieve the standard logger instance
		l := logger.Get()

		// create a correlation ID for the request
		correlationID := utils.GenerateRandomUUID()

		ctx := context.Background()
		ctx = zax.Set(ctx, []zap.Field{zap.String("correlation_id", correlationID)})

		r = r.WithContext(ctx)

		w.Header().Add("X-Correlation-ID", correlationID)

		r = r.WithContext(logger.WithCtx(ctx, l))

		//TODO: remove body logging
		buf, _ := io.ReadAll(r.Body)
		rdr1 := io.NopCloser(bytes.NewBuffer(buf))
		rdr2 := io.NopCloser(bytes.NewBuffer(buf))
		body, _ := io.ReadAll(rdr1)
		log.Debug("Request received", zap.String("path", r.URL.Path), zap.String("body", string(body)))
		r.Body = rdr2

		next.ServeHTTP(w, r)
	})
}

func populateRoutes(router *mux.Router, routeKey string) {
	routes[routeKey] = make([]model.EndpointDto, 0)
	err := router.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
		tpl, _ := route.GetPathTemplate()
		met, _ := route.GetMethods()
		name := route.GetName()
		endpoint := model.EndpointDto{
			Method:   met[0],
			Name:     strings.ToLower(string(name[0])) + name[1:],
			Uuid:     utils.DeterministicGUID(met[0] + tpl),
			Context:  tpl,
			Required: true,
		}
		log.Debug(strings.Join(met, ", ") + " " + tpl)
		routes[routeKey] = append(routes[routeKey], endpoint)
		return nil
	})
	if err != nil {
		log.Error("Unable to walk routers:" + err.Error())
	}
}

func scheduleCleanup(repo *db.DiscoveryRepository) {
	// Perform the cleanup
	for {
		now := time.Now()
		// Truncate to today's midnight, then add 24 hours to get the next midnight
		nextRun := now.Truncate(24 * time.Hour).Add(24 * time.Hour)

		// Sleep until the next run time
		time.Sleep(time.Until(nextRun))

		// Perform the cleanup
		err := repo.DeleteOrphanedCertificates()
		if err != nil {
			log.Error("Failed to delete orphaned certificates", zap.Error(err))
		} else {
			log.Info("Successfully deleted orphaned certificates")
		}
	}
}
