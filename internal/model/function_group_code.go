package model

import (
	"fmt"
)

// FunctionGroupCode : Enumerated code of functional group
type FunctionGroupCode string

// List of FunctionGroupCode
const (
	CREDENTIAL_PROVIDER       FunctionGroupCode = "credentialProvider"
	LEGACY_AUTHORITY_PROVIDER FunctionGroupCode = "legacyAuthorityProvider"
	AUTHORITY_PROVIDER        FunctionGroupCode = "authorityProvider"
	DISCOVERY_PROVIDER        FunctionGroupCode = "discoveryProvider"
	ENTITY_PROVIDER           FunctionGroupCode = "entityProvider"
	COMPLIANCE_PROVIDER       FunctionGroupCode = "complianceProvider"
	CRYPTOGRAPHY_PROVIDER     FunctionGroupCode = "cryptographyProvider"
	NOTIFICATION_PROVIDER     FunctionGroupCode = "notificationProvider"
)

// AllowedFunctionGroupCodeEnumValues is all the allowed values of FunctionGroupCode enum
var AllowedFunctionGroupCodeEnumValues = []FunctionGroupCode{
	"credentialProvider",
	"legacyAuthorityProvider",
	"authorityProvider",
	"discoveryProvider",
	"entityProvider",
	"complianceProvider",
	"cryptographyProvider",
	"notificationProvider",
}

// validFunctionGroupCodeEnumValue provides a map of FunctionGroupCodes for fast verification of use input
var validFunctionGroupCodeEnumValues = map[FunctionGroupCode]struct{}{
	"credentialProvider":      {},
	"legacyAuthorityProvider": {},
	"authorityProvider":       {},
	"discoveryProvider":       {},
	"entityProvider":          {},
	"complianceProvider":      {},
	"cryptographyProvider":    {},
	"notificationProvider":    {},
}

// IsValid return true if the value is valid for the enum, false otherwise
func (v FunctionGroupCode) IsValid() bool {
	_, ok := validFunctionGroupCodeEnumValues[v]
	return ok
}

// NewFunctionGroupCodeFromValue returns a pointer to a valid FunctionGroupCode
// for the value passed as argument, or an error if the value passed is not allowed by the enum
func NewFunctionGroupCodeFromValue(v string) (FunctionGroupCode, error) {
	ev := FunctionGroupCode(v)
	if ev.IsValid() {
		return ev, nil
	} else {
		return "", fmt.Errorf("invalid value '%v' for FunctionGroupCode: valid values are %v", v, AllowedFunctionGroupCodeEnumValues)
	}
}

// AssertFunctionGroupCodeRequired checks if the required fields are not zero-ed
func AssertFunctionGroupCodeRequired(obj FunctionGroupCode) error {
	return nil
}

// AssertFunctionGroupCodeConstraints checks if the values respects the defined constraints
func AssertFunctionGroupCodeConstraints(obj FunctionGroupCode) error {
	return nil
}
