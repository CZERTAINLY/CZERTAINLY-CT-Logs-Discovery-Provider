package model

// BaseAttributeConstraint - Optional regular expressions and constraints used for validating the Attribute content
type BaseAttributeConstraint struct {

	// Description of the constraint
	Description string `json:"description,omitempty"`

	// Error message to be displayed for wrong data
	ErrorMessage string `json:"errorMessage,omitempty"`

	Type AttributeConstraintType `json:"type"`

	// Attribute Constraint Data
	Data map[string]interface{} `json:"data"`
}

// AssertBaseAttributeConstraintRequired checks if the required fields are not zero-ed
func AssertBaseAttributeConstraintRequired(obj BaseAttributeConstraint) error {
	elements := map[string]interface{}{
		"type": obj.Type,
		"data": obj.Data,
	}
	for name, el := range elements {
		if isZero := IsZeroValue(el); isZero {
			return &RequiredError{Field: name}
		}
	}

	return nil
}

// AssertBaseAttributeConstraintConstraints checks if the values respects the defined constraints
func AssertBaseAttributeConstraintConstraints(obj BaseAttributeConstraint) error {
	return nil
}
