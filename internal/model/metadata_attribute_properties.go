package model

// MetadataAttributeProperties - Properties of the Attributes
type MetadataAttributeProperties struct {

	// Friendly name of the Attribute
	Label string `json:"label"`

	// Boolean determining if the Attribute is visible and can be displayed, otherwise it should be hidden to the user.
	Visible bool `json:"visible"`

	// Group of the Attribute, used for the logical grouping of the Attribute
	Group string `json:"group,omitempty"`

	// Boolean determining if the Metadata is a global metadata.
	Global bool `json:"global,omitempty"`

	// Boolean determining if the new metadata content should overwrite (replace) existing content instead of appending.
	Overwrite bool `json:"overwrite,omitempty"`
}

// AssertMetadataAttributePropertiesRequired checks if the required fields are not zero-ed
func AssertMetadataAttributePropertiesRequired(obj MetadataAttributeProperties) error {
	elements := map[string]interface{}{
		"label":   obj.Label,
		"visible": obj.Visible,
	}
	for name, el := range elements {
		if isZero := IsZeroValue(el); isZero {
			return &RequiredError{Field: name}
		}
	}

	return nil
}

// AssertMetadataAttributePropertiesConstraints checks if the values respects the defined constraints
func AssertMetadataAttributePropertiesConstraints(obj MetadataAttributeProperties) error {
	return nil
}
