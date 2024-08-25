package model

// DiscoveryProviderCertificateDataDto - Certificate data
type DiscoveryProviderCertificateDataDto struct {

	// Certificate UUID
	Uuid string `json:"uuid"`

	// Base64 encoded Certificate content
	Base64Content string `json:"base64Content"`

	// Metadata for the Certificate
	Meta []MetadataAttribute `json:"meta"`
}

// AssertDiscoveryProviderCertificateDataDtoRequired checks if the required fields are not zero-ed
func AssertDiscoveryProviderCertificateDataDtoRequired(obj DiscoveryProviderCertificateDataDto) error {
	elements := map[string]interface{}{
		"uuid":          obj.Uuid,
		"base64Content": obj.Base64Content,
		"meta":          obj.Meta,
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

// AssertDiscoveryProviderCertificateDataDtoConstraints checks if the values respects the defined constraints
func AssertDiscoveryProviderCertificateDataDtoConstraints(obj DiscoveryProviderCertificateDataDto) error {
	return nil
}
