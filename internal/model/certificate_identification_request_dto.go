package model

import (
	"context"
	"github.com/tidwall/gjson"
)

type CertificateIdentificationRequestDto struct {

	// Base64 Certificate content. (certificate to be identified)
	Certificate string `json:"certificate"`

	// List of RA Profiles attributes
	RaProfileAttributes []Attribute `json:"raProfileAttributes"`
}

func (a *CertificateIdentificationRequestDto) Unmarshal(ctx context.Context, json []byte) {
	a.Certificate = gjson.GetBytes(json, "certificate").String()
	a.RaProfileAttributes = UnmarshalAttributesValues(ctx, []byte(gjson.GetBytes(json, "raProfileAttributes").Raw))
}

// AssertCertificateIdentificationRequestDtoRequired checks if the required fields are not zero-ed
func AssertCertificateIdentificationRequestDtoRequired(obj CertificateIdentificationRequestDto) error {
	elements := map[string]interface{}{
		"certificate":         obj.Certificate,
		"raProfileAttributes": obj.RaProfileAttributes,
	}
	for name, el := range elements {
		if isZero := IsZeroValue(el); isZero {
			return &RequiredError{Field: name}
		}
	}

	for _, el := range obj.RaProfileAttributes {
		if err := AssertRequestAttributeDtoRequired(el); err != nil {
			return err
		}
	}
	return nil
}

// AssertCertificateIdentificationRequestDtoConstraints checks if the values respects the defined constraints
func AssertCertificateIdentificationRequestDtoConstraints(obj CertificateIdentificationRequestDto) error {
	return nil
}
