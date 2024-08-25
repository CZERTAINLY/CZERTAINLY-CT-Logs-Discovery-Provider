package model

import (
	"fmt"
)

// AttributeContentType : Type of the attribute content.
type AttributeContentType string

// List of AttributeContentType
const (
	STRING     AttributeContentType = "string"
	TEXT       AttributeContentType = "text"
	INTEGER    AttributeContentType = "integer"
	BOOLEAN    AttributeContentType = "boolean"
	FLOAT      AttributeContentType = "float"
	DATE       AttributeContentType = "date"
	TIME       AttributeContentType = "time"
	DATETIME   AttributeContentType = "datetime"
	SECRET     AttributeContentType = "secret"
	FILE       AttributeContentType = "file"
	CREDENTIAL AttributeContentType = "credential"
	CODEBLOCK  AttributeContentType = "codeblock"
	OBJECT     AttributeContentType = "object"
)

// AllowedAttributeContentTypeEnumValues is all the allowed values of AttributeContentType enum
var AllowedAttributeContentTypeEnumValues = []AttributeContentType{
	"string",
	"text",
	"integer",
	"boolean",
	"float",
	"date",
	"time",
	"datetime",
	"secret",
	"file",
	"credential",
	"codeblock",
	"object",
}

// validAttributeContentTypeEnumValue provides a map of AttributeContentTypes for fast verification of use input
var validAttributeContentTypeEnumValues = map[AttributeContentType]struct{}{
	"string":     {},
	"text":       {},
	"integer":    {},
	"boolean":    {},
	"float":      {},
	"date":       {},
	"time":       {},
	"datetime":   {},
	"secret":     {},
	"file":       {},
	"credential": {},
	"codeblock":  {},
	"object":     {},
}

// IsValid return true if the value is valid for the enum, false otherwise
func (v AttributeContentType) IsValid() bool {
	_, ok := validAttributeContentTypeEnumValues[v]
	return ok
}

// NewAttributeContentTypeFromValue returns a pointer to a valid AttributeContentType
// for the value passed as argument, or an error if the value passed is not allowed by the enum
func NewAttributeContentTypeFromValue(v string) (AttributeContentType, error) {
	ev := AttributeContentType(v)
	if ev.IsValid() {
		return ev, nil
	} else {
		return "", fmt.Errorf("invalid value '%v' for AttributeContentType: valid values are %v", v, AllowedAttributeContentTypeEnumValues)
	}
}

// AssertAttributeContentTypeRequired checks if the required fields are not zero-ed
func AssertAttributeContentTypeRequired(obj AttributeContentType) error {
	return nil
}

// AssertAttributeContentTypeConstraints checks if the values respects the defined constraints
func AssertAttributeContentTypeConstraints(obj AttributeContentType) error {
	return nil
}
