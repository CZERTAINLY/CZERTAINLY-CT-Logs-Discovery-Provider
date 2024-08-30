#!/bin/sh

czertainlyHome="/opt/czertainly"
source ${czertainlyHome}/static-functions

log "INFO" "Launching CT Logs Discovery Provider"
./appbin

#exec "$@"