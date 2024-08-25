package model

import (
	"CZERTAINLY-CT-Logs-Discovery-Provider/internal/logger"
	"context"
	"encoding/json"
	"fmt"
	"github.com/tidwall/gjson"
	"github.com/yuseferi/zax/v2"
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
	DISCOVERY_DATA_ATTRIBUTE_API_KEY_DESCRIPTION string = "SSLMate API Key for your subscription"

	DISCOVERY_DATA_ATTRIBUTE_DOMAIN_UUID        string = "80ca4681-01a3-45c0-a606-ea46990eba6d"
	DISCOVERY_DATA_ATTRIBUTE_DOMAIN_NAME        string = "data_domain"
	DISCOVERY_DATA_ATTRIBUTE_DOMAIN_LABEL       string = "Domain"
	DISCOVERY_DATA_ATTRIBUTE_DOMAIN_DESCRIPTION string = "Domain for which you want to discover certificates. " +
		"It must be a registered domain or subordinate to a registered domain. For example, www.example.com and example.com are valid, but com is not."
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
	attributeList := []Attribute{}
	attributeList = append(attributeList, getDiscoveryAttributes()...)

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
		//TODO: remove conversion to string after UI will be able to handle ObjectAttributeContent
		stringData := StringAttributeContent{}
		err := json.Unmarshal(content, &stringData)
		result = ObjectAttributeContent{
			Reference: stringData.Reference,
			Data:      map[string]interface{}{"objectData": stringData.Data},
		}
		if err != nil {
			// log.With(zax.Get(ctx)...).Warn(err.Error(), zap.String("content", string(content)))
			objectData := ObjectAttributeContent{}
			err := json.Unmarshal(content, &objectData)
			if err != nil {
				log.Error(err.Error(), zap.String("content", string(content)))
			}
			result = objectData
		}
	case BOOLEAN:
		booleanContent := BooleanAttributeContent{}
		err := json.Unmarshal(content, &booleanContent)
		result = booleanContent
		if err != nil {
			log.Error(err.Error(), zap.String("content", string(content)))
		}

	case SECRET:
		//TODO: remove conversion to string after UI will be able to handle SecretAttributeContentData
		//secretAttributeContent := SecretAttributeContent{}
		stringData := StringAttributeContent{}
		err := json.Unmarshal(content, &stringData)
		result = SecretAttributeContent{
			Reference: stringData.Reference,
			Data: SecretAttributeContentData{
				Secret: stringData.Data,
			},
		}
		if err != nil {
			log.With(zax.Get(ctx)...).Warn(err.Error(), zap.String("content", string(content)))
			// log.Warn(err.Error(), zap.String("content", string(content)))
			secretData := SecretAttributeContent{}
			err := json.Unmarshal(content, &secretData)
			if err != nil {
				log.Debug(err.Error(), zap.String("content", string(content)))
				log.Error(err.Error())
			}
			result = secretData
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

		//secretContents := gjson.GetBytes(content, "data.attributes.0.content")
		//
		//// take the first secret content
		//secretContent := secretContents.Array()[0]
		//
		//byteContent := []byte(secretContent.Raw)
		//secretDataContent := SecretAttributeContent{}
		//err := json.Unmarshal(byteContent, &secretDataContent)
		//result = secretDataContent
		//if err != nil {
		//	log.Error(err.Error(), zap.String("content", string(byteContent)))
		//}
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
				Required:    true,
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
	}

}
