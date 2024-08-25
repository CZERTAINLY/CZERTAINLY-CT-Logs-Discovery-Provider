package model

// CustomAttributeProperties - Properties of the Attributes
type CustomAttributeProperties struct {

	// Friendly name of the Attribute
	Label string `json:"label"`

	// Boolean determining if the Attribute is visible and can be displayed, otherwise it should be hidden to the user.
	Visible bool `json:"visible"`

	// Group of the Attribute, used for the logical grouping of the Attribute
	Group string `json:"group,omitempty"`

	// Boolean determining if the Attribute is required. If true, the Attribute must be provided.
	Required bool `json:"required"`

	// Boolean determining if the Attribute is read only. If true, the Attribute content cannot be changed.
	ReadOnly bool `json:"readOnly"`

	// Boolean determining if the Attribute contains list of values in the content
	List bool `json:"list"`

	// Boolean determining if the Attribute can have multiple values
	MultiSelect bool `json:"multiSelect"`
}

// AssertCustomAttributePropertiesRequired checks if the required fields are not zero-ed
func AssertCustomAttributePropertiesRequired(obj CustomAttributeProperties) error {
	elements := map[string]interface{}{
		"label":       obj.Label,
		"visible":     obj.Visible,
		"required":    obj.Required,
		"readOnly":    obj.ReadOnly,
		"list":        obj.List,
		"multiSelect": obj.MultiSelect,
	}
	for name, el := range elements {
		if isZero := IsZeroValue(el); isZero {
			return &RequiredError{Field: name}
		}
	}

	return nil
}

// AssertCustomAttributePropertiesConstraints checks if the values respects the defined constraints
func AssertCustomAttributePropertiesConstraints(obj CustomAttributeProperties) error {
	return nil
}
