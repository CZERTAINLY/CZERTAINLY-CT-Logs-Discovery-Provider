package model

type DateAttributeContent struct {

	// Content Reference
	Reference string `json:"reference,omitempty"`

	// Date attribute value in format yyyy-MM-dd
	Data string `json:"data"`
}

// AssertDateAttributeContentRequired checks if the required fields are not zero-ed
func AssertDateAttributeContentRequired(obj DateAttributeContent) error {
	elements := map[string]interface{}{
		"data": obj.Data,
	}
	for name, el := range elements {
		if isZero := IsZeroValue(el); isZero {
			return &RequiredError{Field: name}
		}
	}

	return nil
}

// AssertDateAttributeContentConstraints checks if the values respects the defined constraints
func AssertDateAttributeContentConstraints(obj DateAttributeContent) error {
	return nil
}
