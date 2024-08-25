package model

type CertificateDataResponseDto struct {

	// Base64 encoded Certificate content
	CertificateData string `json:"certificateData"`

	// UUID of Certificate
	Uuid string `json:"uuid,omitempty"`

	// Metadata for the Certificate
	Meta []MetadataAttribute `json:"meta,omitempty"`

	CertificateType CertificateType `json:"certificateType,omitempty"`
}

// AssertCertificateDataResponseDtoRequired checks if the required fields are not zero-ed
func AssertCertificateDataResponseDtoRequired(obj CertificateDataResponseDto) error {
	elements := map[string]interface{}{
		"certificateData": obj.CertificateData,
	}
	for name, el := range elements {
		if isZero := IsZeroValue(el); isZero {
			return &RequiredError{Field: name}
		}
	}

	for _, el := range obj.Meta {
		if err := AssertMetadataAttributeRequired(el); err != nil {
			return err
		}
	}
	return nil
}

// AssertCertificateDataResponseDtoConstraints checks if the values respects the defined constraints
func AssertCertificateDataResponseDtoConstraints(obj CertificateDataResponseDto) error {
	return nil
}
