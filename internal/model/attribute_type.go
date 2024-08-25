package model

import (
	"fmt"
)

// AttributeType : Type of the attribute. It is optional and must be set only if special behaviour is needed.
type AttributeType string

// List of AttributeType
const (
	DATA   AttributeType = "data"
	GROUP  AttributeType = "group"
	INFO   AttributeType = "info"
	META   AttributeType = "meta"
	CUSTOM AttributeType = "custom"
)

// AllowedAttributeTypeEnumValues is all the allowed values of AttributeType enum
var AllowedAttributeTypeEnumValues = []AttributeType{
	"data",
	"group",
	"info",
	"meta",
	"custom",
}

// validAttributeTypeEnumValue provides a map of AttributeTypes for fast verification of use input
var validAttributeTypeEnumValues = map[AttributeType]struct{}{
	"data":   {},
	"group":  {},
	"info":   {},
	"meta":   {},
	"custom": {},
}

// IsValid return true if the value is valid for the enum, false otherwise
func (v AttributeType) IsValid() bool {
	_, ok := validAttributeTypeEnumValues[v]
	return ok
}

// NewAttributeTypeFromValue returns a pointer to a valid AttributeType
// for the value passed as argument, or an error if the value passed is not allowed by the enum
func NewAttributeTypeFromValue(v string) (AttributeType, error) {
	ev := AttributeType(v)
	if ev.IsValid() {
		return ev, nil
	} else {
		return "", fmt.Errorf("invalid value '%v' for AttributeType: valid values are %v", v, AllowedAttributeTypeEnumValues)
	}
}

// AssertAttributeTypeRequired checks if the required fields are not zero-ed
func AssertAttributeTypeRequired(obj AttributeType) error {
	return nil
}

// AssertAttributeTypeConstraints checks if the values respects the defined constraints
func AssertAttributeTypeConstraints(obj AttributeType) error {
	return nil
}
