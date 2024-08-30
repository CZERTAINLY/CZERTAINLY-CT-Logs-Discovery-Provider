package model

import (
	"context"
	"testing"
)

func TestUnmarshalDataAttributesWithStringContent(t *testing.T) {
	JSON_STRING := `
[
	{
		"name": "data_domain",
		"content": [
			{
				"data": "sslmate.com"
			}
		],
        "contentType": "string",
        "uuid": "80ca4681-01a3-45c0-a606-ea46990eba6d"
	}
]	
`
	result := UnmarshalAttributes(context.Background(), []byte(JSON_STRING))

	if len(result) != 1 {
		t.Errorf("Expected 1 attribute, got %d", len(result))
	}
}

func TestUnmarshalMetadataAttributesWithStringContent(t *testing.T) {
	JSON_STRING := `
[
	{
		"uuid": "8929217a-c42b-4eee-995f-c999cf7d1f12",
		"name": "metadata_failureReason",
		"description": "Reason for the failure of the discovery process.",
		"content": [
			{
				"reference": "failureReason",
				"data": "You have exceeded the domain search rate limit for the SSLMate CT Search API.  Please try again later, or authenticate with an API key, which you can obtain by signing up at <https://sslmate.com/signup?for=ct_search_api>."
			}
		],
		"type": "meta",
		"contentType": "string",
		"properties": {
			"label": "Failure Reason",
			"visible": true
		}
	}
]
`
	result := UnmarshalAttributes(context.Background(), []byte(JSON_STRING))

	if len(result) != 1 {
		t.Errorf("Expected 1 attribute, got %d", len(result))
	}
}
