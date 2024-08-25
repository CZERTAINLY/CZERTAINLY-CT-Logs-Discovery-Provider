package model

import (
	"fmt"
)

// AttributeConstraintType : Attribute Constraint Type
type AttributeConstraintType string

// List of AttributeConstraintType
const (
	REG_EXP   AttributeConstraintType = "regExp"
	RANGE     AttributeConstraintType = "range"
	DATE_TIME AttributeConstraintType = "dateTime"
)

// AllowedAttributeConstraintTypeEnumValues is all the allowed values of AttributeConstraintType enum
var AllowedAttributeConstraintTypeEnumValues = []AttributeConstraintType{
	"regExp",
	"range",
	"dateTime",
}

// validAttributeConstraintTypeEnumValue provides a map of AttributeConstraintTypes for fast verification of use input
var validAttributeConstraintTypeEnumValues = map[AttributeConstraintType]struct{}{
	"regExp":   {},
	"range":    {},
	"dateTime": {},
}

// IsValid return true if the value is valid for the enum, false otherwise
func (v AttributeConstraintType) IsValid() bool {
	_, ok := validAttributeConstraintTypeEnumValues[v]
	return ok
}

// NewAttributeConstraintTypeFromValue returns a pointer to a valid AttributeConstraintType
// for the value passed as argument, or an error if the value passed is not allowed by the enum
func NewAttributeConstraintTypeFromValue(v string) (AttributeConstraintType, error) {
	ev := AttributeConstraintType(v)
	if ev.IsValid() {
		return ev, nil
	} else {
		return "", fmt.Errorf("invalid value '%v' for AttributeConstraintType: valid values are %v", v, AllowedAttributeConstraintTypeEnumValues)
	}
}

// AssertAttributeConstraintTypeRequired checks if the required fields are not zero-ed
func AssertAttributeConstraintTypeRequired(obj AttributeConstraintType) error {
	return nil
}

// AssertAttributeConstraintTypeConstraints checks if the values respects the defined constraints
func AssertAttributeConstraintTypeConstraints(obj AttributeConstraintType) error {
	return nil
}
