#!/bin/sh

home="/opt/ct-logs-discovery-provider"
source ${home}/static-functions

log "INFO" "Launching the CT Logs Discovery Provider"
./appbin
