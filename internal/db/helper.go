package db

import (
	"github.com/OmniTrustILM/ct-logs-discovery-provider/internal/config"
	"github.com/lib/pq"
)

func tbl(name string) string {
	return pq.QuoteIdentifier(config.Get().Database.Schema) +
		"." + pq.QuoteIdentifier(name)
}
