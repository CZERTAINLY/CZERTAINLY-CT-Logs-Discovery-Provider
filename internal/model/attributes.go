package model

import (
	"CZERTAINLY-CT-Logs-Discovery-Provider/internal/logger"
	"context"
	"encoding/json"
	"fmt"
	"github.com/tidwall/gjson"
	"go.uber.org/zap"
	"strings"
)

var log = logger.Get()

const (
	CONNECTOR_KIND = "CTLogs-SSLMate"

	// Discovery Attributes
	DISCOVERY_INFO_ATTRIBUTE_OVERVIEW_UUID        string = "9cd99c94-18ad-4802-aed7-7997e0ecdbc2"
	DISCOVERY_INFO_ATTRIBUTE_OVERVIEW_NAME        string = "info_overview"
	DISCOVERY_INFO_ATTRIBUTE_OVERVIEW_LABEL       string = "Overview"
	DISCOVERY_INFO_ATTRIBUTE_OVERVIEW_DESCRIPTION string = "About SSLMate Discovery"

	DISCOVERY_DATA_ATTRIBUTE_API_KEY_UUID        string = "524fea89-3421-4991-8d12-330cba803773"
	DISCOVERY_DATA_ATTRIBUTE_API_KEY_NAME        string = "data_apiKey"
	DISCOVERY_DATA_ATTRIBUTE_API_KEY_LABEL       string = "API Key"
	DISCOVERY_DATA_ATTRIBUTE_API_KEY_DESCRIPTION string = "SSLMate API Key for your subscription. When the API Key is not provided, the connector will use the Free Tier which is limited in the number of requests."

	DISCOVERY_DATA_ATTRIBUTE_DOMAIN_UUID        string = "80ca4681-01a3-45c0-a606-ea46990eba6d"
	DISCOVERY_DATA_ATTRIBUTE_DOMAIN_NAME        string = "data_domain"
	DISCOVERY_DATA_ATTRIBUTE_DOMAIN_LABEL       string = "Domain"
	DISCOVERY_DATA_ATTRIBUTE_DOMAIN_DESCRIPTION string = "Domain for which you want to discover certificates. " +
		"It must be a registered domain or subordinate to a registered domain. For example, www.example.com and example.com are valid, but com is not."

	DISCOVERY_DATA_ATTRIBUTE_INCLUDE_SUBDOMAINS_UUID        string = "a1367844-566f-4bd6-97a3-2e0aea2c1478"
	DISCOVERY_DATA_ATTRIBUTE_INCLUDE_SUBDOMAINS_NAME        string = "data_includeSubdomains"
	DISCOVERY_DATA_ATTRIBUTE_INCLUDE_SUBDOMAINS_LABEL       string = "Include Subdomains"
	DISCOVERY_DATA_ATTRIBUTE_INCLUDE_SUBDOMAINS_DESCRIPTION string = "Discover issuances that are valid for sub-domains (of any depth) of selected domain. Default is false."

	DISCOVERY_DATA_ATTRIBUTE_MATCH_WILDCARDS_UUID        string = "73de185d-2bc3-47db-9880-1fe7b5012df6"
	DISCOVERY_DATA_ATTRIBUTE_MATCH_WILDCARDS_NAME        string = "data_matchWildcards"
	DISCOVERY_DATA_ATTRIBUTE_MATCH_WILDCARDS_LABEL       string = "Match Wildcards"
	DISCOVERY_DATA_ATTRIBUTE_MATCH_WILDCARDS_DESCRIPTION string = "Discover issuances for wildcard DNS names that match selected domain. For example, a request for domain=www.example.com&match_wildcards=true will return issuances for *.example.com. Default is false."

	DISCOVERY_DATA_ATTRIBUTE_AFTER_UUID        string = "466b3f0f-5365-45b2-bc98-4756f585eb7a"
	DISCOVERY_DATA_ATTRIBUTE_AFTER_NAME        string = "data_after"
	DISCOVERY_DATA_ATTRIBUTE_AFTER_LABEL       string = "After"
	DISCOVERY_DATA_ATTRIBUTE_AFTER_DESCRIPTION string = "Discover only issuances that were logged after this date (inclusive). By default, all issuances are discovered."

	DISCOVERY_DATA_ATTRIBUTE_BEFORE_UUID        string = "2293b505-522f-4ded-af57-79bb2a820d6c"
	DISCOVERY_DATA_ATTRIBUTE_BEFORE_NAME        string = "data_before"
	DISCOVERY_DATA_ATTRIBUTE_BEFORE_LABEL       string = "Before"
	DISCOVERY_DATA_ATTRIBUTE_BEFORE_DESCRIPTION string = "Discover only issuances that were logged before this date (exclusive). Must be at least 15 minutes before the current time. By default, all issuances are discovered."

	DISCOVERY_METADATA_ATTRIBUTE_FAILURE_REASON_UUID        string = "8929217a-c42b-4eee-995f-c999cf7d1f12"
	DISCOVERY_METADATA_ATTRIBUTE_FAILURE_REASON_NAME        string = "metadata_failureReason"
	DISCOVERY_METADATA_ATTRIBUTE_FAILURE_REASON_LABEL       string = "Failure Reason"
	DISCOVERY_METADATA_ATTRIBUTE_FAILURE_REASON_DESCRIPTION string = "Reason for the failure of the discovery process."

	CERTIFICATE_METADATA_ATTRIBUTE_SSLMATE_FRIENDLY_NAME_UUID        string = "675d8f18-9ab3-4677-b0de-2a2e6a3cbf29"
	CERTIFICATE_METADATA_ATTRIBUTE_SSLMATE_FRIENDLY_NAME_NAME        string = "metadata_sslmateFriendlyName"
	CERTIFICATE_METADATA_ATTRIBUTE_SSLMATE_FRIENDLY_NAME_LABEL       string = "Friendly Name"
	CERTIFICATE_METADATA_ATTRIBUTE_SSLMATE_FRIENDLY_NAME_DESCRIPTION string = "The organization which issued the certificate. This name is curated by SSLMate to be an accurate and helpful way to identify the issuer of a certificate."

	CERTIFICATE_METADATA_ATTRIBUTE_SSLMATE_CAA_DOMAINS_UUID        string = "60f5dfc6-eae7-4ae3-81bc-9758a8acfcff"
	CERTIFICATE_METADATA_ATTRIBUTE_SSLMATE_CAA_DOMAINS_NAME        string = "metadata_sslmateCaaDomains"
	CERTIFICATE_METADATA_ATTRIBUTE_SSLMATE_CAA_DOMAINS_LABEL       string = "CAA Domains"
	CERTIFICATE_METADATA_ATTRIBUTE_SSLMATE_CAA_DOMAINS_DESCRIPTION string = "The domain names which can be placed in a CAA record to authorize the issuer."

	CERTIFICATE_METADATA_ATTRIBUTE_SSLMATE_PROBLEM_REPORTING_UUID        string = "65c58eb2-6b6f-4520-af83-2a1543a1ec38"
	CERTIFICATE_METADATA_ATTRIBUTE_SSLMATE_PROBLEM_REPORTING_NAME        string = "metadata_sslmateProblemReporting"
	CERTIFICATE_METADATA_ATTRIBUTE_SSLMATE_PROBLEM_REPORTING_LABEL       string = "Problem Reporting"
	CERTIFICATE_METADATA_ATTRIBUTE_SSLMATE_PROBLEM_REPORTING_DESCRIPTION string = "Instructions on how to request the certificate be revoked."
)

type AttributeName string

type CredentialType string

func GetAttributeDefByUUID(uuid string) Attribute {
	for _, attr := range GetAttributeList() {
		if attr.GetUuid() == uuid {
			return attr
		}
	}
	return nil
}

func GetAttributeDefByName(name string) Attribute {
	for _, attr := range GetAttributeList() {
		if attr.GetName() == name {
			return attr
		}
	}
	return nil
}

const (
	DisoveryAttributes string = "DiscoveryAttributes"
)

func GetAttributeListBySet(attributeSet string) []Attribute {
	switch attributeSet {
	case DisoveryAttributes:
		return getDiscoveryAttributes()
	}

	return nil
}

func GetAttributeList() []Attribute {
	var attributeList []Attribute
	attributeList = append(attributeList, getDiscoveryAttributes()...)
	// append list with the CreateFailureReasonMetadataAttribute
	attributeList = append(attributeList, CreateFailureReasonMetadataAttribute("dummy"))
	// append list with the CreateSSLMateFriendlyNameMetadataAttribute
	attributeList = append(attributeList, CreateSSLMateFriendlyNameMetadataAttribute("dummy"))
	// append list with the CreateSSLMateCaaDomainsMetadataAttribute
	attributeList = append(attributeList, CreateSSLMateCaaDomainsMetadataAttribute([]string{"dummy"}))
	// append list with the CreateSSLMateProblemReportingMetadataAttribute
	attributeList = append(attributeList, CreateSSLMateProblemReportingMetadataAttribute("dummy"))

	return attributeList
}

func GetAtributeByUUID(uuid string) AttributeDefinition {
	for _, attr := range GetAttributeList() {
		if attr.GetUuid() == uuid {
			return AttributeDefinition{
				Name:                 attr.GetName(),
				Uuid:                 attr.GetUuid(),
				AttributeType:        attr.GetAttributeType(),
				AttributeContentType: attr.GetAttributeContentType(),
			}
		}
	}
	return AttributeDefinition{}
}

func GetAttributeByName(name string) AttributeDefinition {
	for _, attr := range GetAttributeList() {
		if attr.GetName() == name {
			return AttributeDefinition{
				Name:                 attr.GetName(),
				Uuid:                 attr.GetUuid(),
				AttributeType:        attr.GetAttributeType(),
				AttributeContentType: attr.GetAttributeContentType(),
			}
		}
	}
	return AttributeDefinition{}
}

func unmarshalAttributeContent(ctx context.Context, content []byte, contentType AttributeContentType) AttributeContent {
	var result AttributeContent
	switch contentType {
	case STRING:
		stringContent := StringAttributeContent{}
		err := json.Unmarshal(content, &stringContent)
		result = stringContent
		if err != nil {
			log.Error(err.Error(), zap.String("content", string(content)))
		}
	case OBJECT:
		objectData := ObjectAttributeContent{}
		err := json.Unmarshal(content, &objectData)
		if err != nil {
			log.Error(err.Error(), zap.String("content", string(content)))
		}
		result = objectData
	case BOOLEAN:
		booleanContent := BooleanAttributeContent{}
		err := json.Unmarshal(content, &booleanContent)
		result = booleanContent
		if err != nil {
			log.Error(err.Error(), zap.String("content", string(content)))
		}
	case SECRET:
		secretData := SecretAttributeContent{}
		err := json.Unmarshal(content, &secretData)
		if err != nil {
			log.Debug(err.Error(), zap.String("content", string(content)))
			log.Error(err.Error())
		}
		result = secretData
	case DATETIME:
		dateTimeContent := DateTimeAttributeContent{}
		err := json.Unmarshal(content, &dateTimeContent)
		result = dateTimeContent
		if err != nil {
			log.Error(err.Error(), zap.String("content", string(content)))
		}
	case CREDENTIAL: // we assume here to get only ApiKey as secret attribute content
		credentialContent := CredentialAttributeContent{}
		err := json.Unmarshal(content, &credentialContent)

		// credential content has nested attributes with content
		for i, attr := range credentialContent.Data.Attributes {
			attrContents := gjson.GetBytes(content, fmt.Sprintf("data.attributes.%d.content", i))
			for _, attrContent := range attrContents.Array() {
				credentialContent.Data.Attributes[i].Content[i] = unmarshalAttributeContent(ctx, []byte(attrContent.Raw), attr.ContentType)
				//attr.Content = append(attr.Content, unmarshalAttributeContent([]byte(attrContent.Raw), attr.ContentType))
			}
		}

		result = credentialContent
		if err != nil {
			// TODO:  json: cannot unmarshal object into Go struct field DataAttribute.data.attributes.content of type model.AttributeContent
			// if error message contains this string, then we have a problem with unmarshalling the content
			if !strings.HasPrefix(err.Error(), "json: cannot unmarshal object into Go struct field DataAttribute.data.attributes.content of type model.AttributeContent") {
				log.Error(err.Error(), zap.String("content", string(content)))
			}
		}
	}

	return result
}

func unmarshalAttribute(ctx context.Context, content []byte, attrDef AttributeDefinition) Attribute {
	var result Attribute
	switch attrDef.AttributeType {
	case DATA:

		data := DataAttribute{}
		contents := gjson.GetBytes(content, "content")
		for _, content := range contents.Array() {
			data.Content = append(data.Content, unmarshalAttributeContent(ctx, []byte(content.Raw), attrDef.AttributeContentType))
		}
		data.Uuid = gjson.GetBytes(content, "uuid").String()
		data.Name = gjson.GetBytes(content, "name").String()
		data.Description = gjson.GetBytes(content, "description").String()
		data.Type = attrDef.AttributeType
		data.ContentType = attrDef.AttributeContentType
		properties := gjson.GetBytes(content, "properties").Raw
		if properties != "" {
			err := json.Unmarshal([]byte(properties), &data.Properties)
			if err != nil {
				log.Error(err.Error(), zap.String("content", string(content)))
			}
		}
		constraints := gjson.GetBytes(content, "constrains").Raw
		if constraints != "" {
			err := json.Unmarshal([]byte(constraints), &data.Constraints)
			if err != nil {
				log.Error(err.Error(), zap.String("content", string(content)))
			}
		}
		callbacks := gjson.GetBytes(content, "attributeCallback").Raw
		if callbacks != "" {
			err := json.Unmarshal([]byte(callbacks), &data.AttributeCallback)
			if err != nil {
				log.Error(err.Error(), zap.String("content", string(content)))
			}
		}
		result = data

	case META:
		meta := MetadataAttribute{}
		contents := gjson.GetBytes(content, "content")
		for _, content := range contents.Array() {
			meta.Content = append(meta.Content, unmarshalAttributeContent(ctx, []byte(content.Raw), attrDef.AttributeContentType))
		}
		meta.Uuid = gjson.GetBytes(content, "uuid").String()
		meta.Name = gjson.GetBytes(content, "name").String()
		meta.Description = gjson.GetBytes(content, "description").String()
		meta.Type = attrDef.AttributeType
		meta.ContentType = attrDef.AttributeContentType
		properties := gjson.GetBytes(content, "properties").Raw
		if properties != "" {
			err := json.Unmarshal([]byte(properties), &meta.Properties)
			if err != nil {
				log.Error(err.Error(), zap.String("content", string(content)))
			}
		}
		result = meta
	}

	return result
}

func unmarshalAttributeValue(ctx context.Context, content []byte, attrDef AttributeDefinition) Attribute {
	var result Attribute
	switch attrDef.AttributeType {
	case DATA:
		data := GetAttributeDefByName(attrDef.Name).(DataAttribute)
		contents := gjson.GetBytes(content, "content")
		data.Content = []AttributeContent{}
		for _, content := range contents.Array() {
			data.Content = append(data.Content, unmarshalAttributeContent(ctx, []byte(content.Raw), attrDef.AttributeContentType))
		}
		result = data
	}

	return result
}

func UnmarshalAttributesValues(ctx context.Context, content []byte) []Attribute {
	attributes := gjson.GetBytes(content, "@values")
	var result []Attribute
	for _, attribute := range attributes.Array() {
		def := GetAttributeByName(gjson.Get(attribute.Raw, "name").String())
		attributeObject := unmarshalAttributeValue(ctx, []byte(attribute.Raw), def)
		result = append(result, attributeObject)
	}
	return result
}

func UnmarshalAttributes(ctx context.Context, content []byte) []Attribute {
	attributes := gjson.GetBytes(content, "@values")
	var result []Attribute
	for _, attribute := range attributes.Array() {
		definition := AttributeDefinition{}
		err := json.Unmarshal([]byte(attribute.Raw), &definition)
		if err != nil {
			return nil
		}
		if definition.AttributeType == "" || definition.AttributeContentType == "" {
			def := GetAttributeByName(definition.Name)
			definition.AttributeType = def.AttributeType
			definition.AttributeContentType = def.AttributeContentType
		}
		attributeObject := unmarshalAttribute(ctx, []byte(attribute.Raw), definition)
		result = append(result, attributeObject)
	}
	return result
}

func GetAttributeFromArrayByUUID(uuid string, attributes []Attribute) Attribute {
	for _, attr := range attributes {
		if attr.GetUuid() == uuid {
			return attr
		}
	}
	return nil
}

func GetApiKeyFromAttribute(attribute DataAttribute) string {
	credentialContentData := attribute.GetContent()[0].(CredentialAttributeContent).GetData().(CredentialAttributeContentData)
	return credentialContentData.Attributes[0].GetContent()[0].(SecretAttributeContent).GetData().(SecretAttributeContentData).Secret
}

func CreateFailureReasonMetadataAttribute(failureReason string) MetadataAttribute {
	return MetadataAttribute{
		Uuid:        DISCOVERY_METADATA_ATTRIBUTE_FAILURE_REASON_UUID,
		Name:        DISCOVERY_METADATA_ATTRIBUTE_FAILURE_REASON_NAME,
		Description: DISCOVERY_METADATA_ATTRIBUTE_FAILURE_REASON_DESCRIPTION,
		Type:        META,
		Content: []AttributeContent{
			StringAttributeContent{
				Reference: "failureReason",
				Data:      failureReason,
			},
		},
		ContentType: STRING,
		Properties: &MetadataAttributeProperties{
			Label:   DISCOVERY_METADATA_ATTRIBUTE_FAILURE_REASON_LABEL,
			Visible: true,
			Group:   "",
			Global:  false,
		},
	}
}

func CreateSSLMateFriendlyNameMetadataAttribute(friendlyName string) MetadataAttribute {
	return MetadataAttribute{
		Uuid:        CERTIFICATE_METADATA_ATTRIBUTE_SSLMATE_FRIENDLY_NAME_UUID,
		Name:        CERTIFICATE_METADATA_ATTRIBUTE_SSLMATE_FRIENDLY_NAME_NAME,
		Description: CERTIFICATE_METADATA_ATTRIBUTE_SSLMATE_FRIENDLY_NAME_DESCRIPTION,
		Type:        META,
		Content: []AttributeContent{
			StringAttributeContent{
				Reference: "friendlyName",
				Data:      friendlyName,
			},
		},
		ContentType: STRING,
		Properties: &MetadataAttributeProperties{
			Label:     CERTIFICATE_METADATA_ATTRIBUTE_SSLMATE_FRIENDLY_NAME_LABEL,
			Visible:   true,
			Group:     "",
			Global:    false,
			Overwrite: true,
		},
	}
}

func CreateSSLMateCaaDomainsMetadataAttribute(caaDomains []string) MetadataAttribute {
	return MetadataAttribute{
		Uuid:        CERTIFICATE_METADATA_ATTRIBUTE_SSLMATE_CAA_DOMAINS_UUID,
		Name:        CERTIFICATE_METADATA_ATTRIBUTE_SSLMATE_CAA_DOMAINS_NAME,
		Description: CERTIFICATE_METADATA_ATTRIBUTE_SSLMATE_CAA_DOMAINS_DESCRIPTION,
		Type:        META,
		Content: []AttributeContent{
			StringAttributeContent{
				Reference: "caaDomains",
				Data:      strings.Join(caaDomains, ", "),
			},
		},
		ContentType: STRING,
		Properties: &MetadataAttributeProperties{
			Label:     CERTIFICATE_METADATA_ATTRIBUTE_SSLMATE_CAA_DOMAINS_LABEL,
			Visible:   true,
			Group:     "",
			Global:    false,
			Overwrite: true,
		},
	}
}

func CreateSSLMateProblemReportingMetadataAttribute(problemReporting string) MetadataAttribute {
	return MetadataAttribute{
		Uuid:        CERTIFICATE_METADATA_ATTRIBUTE_SSLMATE_PROBLEM_REPORTING_UUID,
		Name:        CERTIFICATE_METADATA_ATTRIBUTE_SSLMATE_PROBLEM_REPORTING_NAME,
		Description: CERTIFICATE_METADATA_ATTRIBUTE_SSLMATE_PROBLEM_REPORTING_DESCRIPTION,
		Type:        META,
		Content: []AttributeContent{
			StringAttributeContent{
				Reference: "problemReporting",
				Data:      problemReporting,
			},
		},
		ContentType: STRING,
		Properties: &MetadataAttributeProperties{
			Label:     CERTIFICATE_METADATA_ATTRIBUTE_SSLMATE_PROBLEM_REPORTING_LABEL,
			Visible:   true,
			Group:     "",
			Global:    false,
			Overwrite: true,
		},
	}
}

func getDiscoveryAttributes() []Attribute {
	return []Attribute{
		InfoAttribute{
			Uuid:        DISCOVERY_INFO_ATTRIBUTE_OVERVIEW_UUID,
			Name:        DISCOVERY_INFO_ATTRIBUTE_OVERVIEW_NAME,
			Description: DISCOVERY_INFO_ATTRIBUTE_OVERVIEW_DESCRIPTION,
			Type:        INFO,
			Content: []AttributeContent{
				TextAttributeContent{
					Data: `### Discover certificates from CT Logs using SSLMate.

This connector allows you to discover certificates from Certificate Transparency (CT) Logs using SSLMate service.
For more information about SSLMate, please visit [SSLMate website](https://sslmate.com/).

You can discover certificates by providing the domain name and optionally the API Key for your SSLMate subscription.
When the API Key is not provided, the connector will use the Free Tier which is limited in the number of requests.

You can discover certificates for a specific time range, include subdomains, and match wildcards.
By default the connector will discover all certificates for the provided domain that are logged in the CT Logs.
You can restrict the discovery to certificates that were logged after a specific date or before a specific date.
`,
				},
			},
			ContentType: TEXT,
			Properties: &InfoAttributeProperties{
				Label:   DISCOVERY_INFO_ATTRIBUTE_OVERVIEW_LABEL,
				Visible: true,
				Group:   "",
			},
		},
		DataAttribute{
			Uuid:        DISCOVERY_DATA_ATTRIBUTE_API_KEY_UUID,
			Name:        DISCOVERY_DATA_ATTRIBUTE_API_KEY_NAME,
			Description: DISCOVERY_DATA_ATTRIBUTE_API_KEY_DESCRIPTION,
			Type:        DATA,
			Content:     nil,
			ContentType: CREDENTIAL,
			Properties: &DataAttributeProperties{
				Label:       DISCOVERY_DATA_ATTRIBUTE_API_KEY_LABEL,
				Visible:     true,
				Group:       "",
				Required:    false,
				ReadOnly:    false,
				List:        true,
				MultiSelect: false,
			},
			AttributeCallback: &AttributeCallback{
				CallbackContext: "core/getCredentials",
				CallbackMethod:  "GET",
				Mappings: []AttributeCallbackMapping{
					{
						To: "credentialKind",
						Targets: []AttributeValueTarget{
							PATH_VARIABLE,
						},
						Value: "ApiKey",
					},
				},
			},
		},
		DataAttribute{
			Uuid:        DISCOVERY_DATA_ATTRIBUTE_DOMAIN_UUID,
			Name:        DISCOVERY_DATA_ATTRIBUTE_DOMAIN_NAME,
			Description: DISCOVERY_DATA_ATTRIBUTE_DOMAIN_DESCRIPTION,
			Type:        DATA,
			Content:     nil,
			ContentType: STRING,
			Properties: &DataAttributeProperties{
				Label:       DISCOVERY_DATA_ATTRIBUTE_DOMAIN_LABEL,
				Visible:     true,
				Group:       "",
				Required:    true,
				ReadOnly:    false,
				List:        false,
				MultiSelect: false,
			},
			Constraints: []AttributeConstraint{
				RegexpAttributeConstraint{
					Description:  "Domain for the SSLMate CT Logs certificate discovery",
					ErrorMessage: "Domain must be a registered domain or subordinate to a registered domain",
					Type:         REG_EXP,
					Data:         "^(?=.{4,253}$)(((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\\.)+[a-zA-Z]{2,63})$",
				},
			},
		},
		DataAttribute{
			Uuid:        DISCOVERY_DATA_ATTRIBUTE_INCLUDE_SUBDOMAINS_UUID,
			Name:        DISCOVERY_DATA_ATTRIBUTE_INCLUDE_SUBDOMAINS_NAME,
			Description: DISCOVERY_DATA_ATTRIBUTE_INCLUDE_SUBDOMAINS_DESCRIPTION,
			Type:        DATA,
			Content: []AttributeContent{
				BooleanAttributeContent{
					Reference: "",
					Data:      false,
				},
			},
			ContentType: BOOLEAN,
			Properties: &DataAttributeProperties{
				Label:       DISCOVERY_DATA_ATTRIBUTE_INCLUDE_SUBDOMAINS_LABEL,
				Visible:     true,
				Group:       "",
				Required:    false,
				ReadOnly:    false,
				List:        false,
				MultiSelect: false,
			},
		},
		DataAttribute{
			Uuid:        DISCOVERY_DATA_ATTRIBUTE_MATCH_WILDCARDS_UUID,
			Name:        DISCOVERY_DATA_ATTRIBUTE_MATCH_WILDCARDS_NAME,
			Description: DISCOVERY_DATA_ATTRIBUTE_MATCH_WILDCARDS_DESCRIPTION,
			Type:        DATA,
			Content: []AttributeContent{
				BooleanAttributeContent{
					Reference: "",
					Data:      false,
				},
			},
			ContentType: BOOLEAN,
			Properties: &DataAttributeProperties{
				Label:       DISCOVERY_DATA_ATTRIBUTE_MATCH_WILDCARDS_LABEL,
				Visible:     true,
				Group:       "",
				Required:    false,
				ReadOnly:    false,
				List:        false,
				MultiSelect: false,
			},
		},
		DataAttribute{
			Uuid:        DISCOVERY_DATA_ATTRIBUTE_AFTER_UUID,
			Name:        DISCOVERY_DATA_ATTRIBUTE_AFTER_NAME,
			Description: DISCOVERY_DATA_ATTRIBUTE_AFTER_DESCRIPTION,
			Type:        DATA,
			Content:     nil,
			ContentType: DATETIME,
			Properties: &DataAttributeProperties{
				Label:       DISCOVERY_DATA_ATTRIBUTE_AFTER_LABEL,
				Visible:     true,
				Group:       "",
				Required:    false,
				ReadOnly:    false,
				List:        false,
				MultiSelect: false,
			},
		},
		DataAttribute{
			Uuid:        DISCOVERY_DATA_ATTRIBUTE_BEFORE_UUID,
			Name:        DISCOVERY_DATA_ATTRIBUTE_BEFORE_NAME,
			Description: DISCOVERY_DATA_ATTRIBUTE_BEFORE_DESCRIPTION,
			Type:        DATA,
			Content:     nil,
			ContentType: DATETIME,
			Properties: &DataAttributeProperties{
				Label:       DISCOVERY_DATA_ATTRIBUTE_BEFORE_LABEL,
				Visible:     true,
				Group:       "",
				Required:    false,
				ReadOnly:    false,
				List:        false,
				MultiSelect: false,
			},
		},
	}
}
