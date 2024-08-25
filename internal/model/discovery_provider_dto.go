package model

import "gorm.io/datatypes"

type DiscoveryProviderDto struct {

	// Object identifier
	Uuid string `json:"uuid"`

	// Object Name
	Name string `json:"name"`

	Status DiscoveryStatus `json:"status"`

	// Number of Certificates discovered
	TotalCertificatesDiscovered int64 `json:"totalCertificatesDiscovered"`

	// Certificate data
	CertificateData []DiscoveryProviderCertificateDataDto `json:"certificateData"`

	// Certificate Metadata
	Meta datatypes.JSON `json:"meta"`
}

// AssertDiscoveryProviderDtoRequired checks if the required fields are not zero-ed
func AssertDiscoveryProviderDtoRequired(obj DiscoveryProviderDto) error {
	elements := map[string]interface{}{
		"uuid":            obj.Uuid,
		"name":            obj.Name,
		"status":          obj.Status,
		"certificateData": obj.CertificateData,
		"meta":            obj.Meta,
	}
	for name, el := range elements {
		if isZero := IsZeroValue(el); isZero {
			return &RequiredError{Field: name}
		}
	}

	//for _, el := range obj.CertificateData {
	//	if err := AssertDiscoveryProviderCertificateDataDtoRequired(el); err != nil {
	//		return err
	//	}
	//}
	//for _, el := range obj.Meta {
	//	if err := AssertMetadataAttributeRequired(el); err != nil {
	//		return err
	//	}
	//}
	return nil
}

// AssertDiscoveryProviderDtoConstraints checks if the values respects the defined constraints
func AssertDiscoveryProviderDtoConstraints(obj DiscoveryProviderDto) error {
	return nil
}
