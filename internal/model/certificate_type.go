package model

import (
	"fmt"
)

// CertificateType : Type of the Certificate
type CertificateType string

// List of CertificateType
const (
	X_509 CertificateType = "X.509"
	SSH   CertificateType = "SSH"
)

// AllowedCertificateTypeEnumValues is all the allowed values of CertificateType enum
var AllowedCertificateTypeEnumValues = []CertificateType{
	"X.509",
	"SSH",
}

// validCertificateTypeEnumValue provides a map of CertificateTypes for fast verification of use input
var validCertificateTypeEnumValues = map[CertificateType]struct{}{
	"X.509": {},
	"SSH":   {},
}

// IsValid return true if the value is valid for the enum, false otherwise
func (v CertificateType) IsValid() bool {
	_, ok := validCertificateTypeEnumValues[v]
	return ok
}

// NewCertificateTypeFromValue returns a pointer to a valid CertificateType
// for the value passed as argument, or an error if the value passed is not allowed by the enum
func NewCertificateTypeFromValue(v string) (CertificateType, error) {
	ev := CertificateType(v)
	if ev.IsValid() {
		return ev, nil
	} else {
		return "", fmt.Errorf("invalid value '%v' for CertificateType: valid values are %v", v, AllowedCertificateTypeEnumValues)
	}
}

// AssertCertificateTypeRequired checks if the required fields are not zero-ed
func AssertCertificateTypeRequired(obj CertificateType) error {
	return nil
}

// AssertCertificateTypeConstraints checks if the values respects the defined constraints
func AssertCertificateTypeConstraints(obj CertificateType) error {
	return nil
}
