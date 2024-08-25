package model

import "github.com/tidwall/gjson"

type CertificateRenewRequestDto struct {
	// Certificate signing request encoded as Base64 string
	Request string `json:"request"`

	// Certificate signing request format
	CertificateRequestFormat CertificateRequestFormat `json:"format"`

	// List of RA Profiles attributes
	RaProfileAttributes []Attribute `json:"raProfileAttributes"`

	// Base64 Certificate content. (Certificate to be renewed)
	Certificate string `json:"certificate"`

	// Metadata for the Certificate
	Meta []Attribute `json:"meta"`
}

func (a *CertificateRenewRequestDto) Unmarshal(json []byte) {
	a.Request = gjson.GetBytes(json, "request").String()
	a.CertificateRequestFormat = CertificateRequestFormat(gjson.GetBytes(json, "format").String())
	a.Certificate = gjson.GetBytes(json, "certificate").String()
	a.RaProfileAttributes = UnmarshalAttributesValues([]byte(gjson.GetBytes(json, "raProfileAttributes").Raw))
}

// AssertCertificateRenewRequestDtoRequired checks if the required fields are not zero-ed
func AssertCertificateRenewRequestDtoRequired(obj CertificateRenewRequestDto) error {
	elements := map[string]interface{}{
		"request":             obj.Request,
		"format":              obj.CertificateRequestFormat,
		"raProfileAttributes": obj.RaProfileAttributes,
		"certificate":         obj.Certificate,
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
	for _, el := range obj.Meta {
		if err := AssertMetadataAttributeRequired(el); err != nil {
			return err
		}
	}
	return nil
}

// AssertCertificateRenewRequestDtoConstraints checks if the values respects the defined constraints
func AssertCertificateRenewRequestDtoConstraints(obj CertificateRenewRequestDto) error {
	return nil
}
