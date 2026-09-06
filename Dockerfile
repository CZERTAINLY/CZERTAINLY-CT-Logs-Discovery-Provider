# syntax=docker/dockerfile
# Install golang

# Build Stage
FROM golang:1.26-alpine3.23 AS builder

ENV WRK_DIR=/app

# Copy the contents to /app
COPY . $WRK_DIR

# Set working directory
WORKDIR $WRK_DIR

# Toggle CGO based on your app requirement. CGO_ENABLED=1 for enabling CGO
RUN CGO_ENABLED=0 go build -ldflags '-s -w -extldflags "-static"' -o $WRK_DIR/appbin $WRK_DIR/cmd

COPY docker /app/docker

#
# Run Stage
#
FROM alpine:3.22

LABEL org.opencontainers.image.authors="ILM <ilm@omnitrust.com>"

# add non root user ct-logs-discovery-provider
RUN apk upgrade --no-cache \
    && addgroup --system --gid 10001 ct-logs-discovery-provider \
    && adduser --system --home /opt/ct-logs-discovery-provider --uid 10001 \
       --ingroup ct-logs-discovery-provider ct-logs-discovery-provider

COPY --from=builder /app/docker /
COPY --from=builder /app /opt/ct-logs-discovery-provider

WORKDIR /opt/ct-logs-discovery-provider

ENV SERVER_PORT=8080
ENV LOG_LEVEL=INFO

USER 10001

ENTRYPOINT ["/opt/ct-logs-discovery-provider/entry.sh"]
