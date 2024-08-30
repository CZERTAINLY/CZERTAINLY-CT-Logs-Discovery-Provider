package model

// BaseAttributeDto - Base Attribute definition
type BaseAttributeDto struct {

	// UUID of the Attribute for unique identification
	Uuid string `json:"uuid"`

	// Name of the Attribute that is used for identification
	Name string `json:"name"`

	// Optional description of the Attribute, should contain helper text on what is expected
	Description string `json:"description,omitempty"`

	Type AttributeType `json:"type"`

	// Content of the Attribute
	Content map[string]interface{} `json:"content,omitempty"`

	ContentType AttributeContentType `json:"contentType"`

	Properties CustomAttributeProperties `json:"properties"`

	// Optional regular expressions and constraints used for validating the Attribute content
	Constraints []BaseAttributeConstraint `json:"constraints,omitempty"`

	AttributeCallback AttributeCallback `json:"attributeCallback,omitempty"`
}

// AssertBaseAttributeDtoRequired checks if the required fields are not zero-ed
func AssertBaseAttributeDtoRequired(obj BaseAttributeDto) error {
	elements := map[string]interface{}{
		"uuid":        obj.Uuid,
		"name":        obj.Name,
		"type":        obj.Type,
		"content":     obj.Content,
		"contentType": obj.ContentType,
		"properties":  obj.Properties,
	}
	for name, el := range elements {
		if isZero := IsZeroValue(el); isZero {
			return &RequiredError{Field: name}
		}
	}

	if err := AssertCustomAttributePropertiesRequired(obj.Properties); err != nil {
		return err
	}
	for _, el := range obj.Constraints {
		if err := AssertBaseAttributeConstraintRequired(el); err != nil {
			return err
		}
	}
	if err := AssertAttributeCallbackRequired(obj.AttributeCallback); err != nil {
		return err
	}
	return nil
}

// AssertBaseAttributeDtoConstraints checks if the values respects the defined constraints
func AssertBaseAttributeDtoConstraints(obj BaseAttributeDto) error {
	return nil
}
