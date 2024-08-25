package model

// AttributeCallbackMapping - Mappings for the callback method
type AttributeCallbackMapping struct {

	// Name of the attribute whose value is to be used as value of path variable or request param or body field.It is optional and must be set only if value is not set.
	From string `json:"from,omitempty"`

	AttributeType AttributeType `json:"attributeType,omitempty"`

	AttributeContentType AttributeContentType `json:"attributeContentType,omitempty"`

	// Name of the path variable or request param or body field which is to be used to assign value of attribute
	To string `json:"to"`

	// Set of targets for propagating value.
	Targets []AttributeValueTarget `json:"targets"`

	// Static value to be propagated to targets. It is optional and is set only if the value is known at attribute creation time.
	Value string `json:"value,omitempty"`
}

// AssertAttributeCallbackMappingRequired checks if the required fields are not zero-ed
func AssertAttributeCallbackMappingRequired(obj AttributeCallbackMapping) error {
	elements := map[string]interface{}{
		"to":      obj.To,
		"targets": obj.Targets,
	}
	for name, el := range elements {
		if isZero := IsZeroValue(el); isZero {
			return &RequiredError{Field: name}
		}
	}

	return nil
}

// AssertAttributeCallbackMappingConstraints checks if the values respects the defined constraints
func AssertAttributeCallbackMappingConstraints(obj AttributeCallbackMapping) error {
	return nil
}
