package sslmate

import (
	"encoding/json"
	"fmt"
)

// checks if the ErrorObject type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &ErrorObject{}

// ErrorMessageDto struct for ErrorMessageDto
type ErrorObject struct {
	// A short machine-readable code that describes the error. The meaning of an error code will never change,
	// although additional error codes may be defined in the future.
	Code string `json:"code"`
	// A human-readable message. The value of this field is only suitable for human consumption; the exact wording
	// of messages may change without notice. For a machine-readable code, use the code field.
	Message string `json:"message"`
	// The name of the request field that caused the error. Only present if the error is field-specific.
	Field string `json:"field,omitempty"`
	// An array of error objects that describe the problem(s) which caused this error in greater detail.
	// Only present for some error types. Sub-errors do not have further sub-errors.
	SubErrors            []ErrorObject `json:"sub_errors,omitempty"`
	AdditionalProperties map[string]interface{}
}

type _ErrorObject ErrorObject

func NewErrorObject(message string) *ErrorObject {
	this := ErrorObject{}
	this.Message = message
	return &this
}

func NewErrorObjectWithDefaults() *ErrorObject {
	this := ErrorObject{}
	return &this
}

func (o *ErrorObject) GetCode() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Code
}

func (o *ErrorObject) GetCodeOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Code, true
}

func (o *ErrorObject) SetCode(v string) {
	o.Code = v
}

// GetMessage returns the Message field value
func (o *ErrorObject) GetMessage() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Message
}

// GetMessageOk returns a tuple with the Message field value
// and a boolean to check if the value has been set.
func (o *ErrorObject) GetMessageOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Message, true
}

// SetMessage sets field value
func (o *ErrorObject) SetMessage(v string) {
	o.Message = v
}

// GetField returns the Field field value
func (o *ErrorObject) GetField() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Field
}

// GetFieldOk returns a tuple with the Field field value
// and a boolean to check if the value has been set.
func (o *ErrorObject) GetFieldOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Field, true
}

// SetField sets field value
func (o *ErrorObject) SetField(v string) {
	o.Field = v
}

func (o *ErrorObject) GetSubErrors() []ErrorObject {
	if o == nil {
		var ret []ErrorObject
		return ret
	}

	return o.SubErrors
}

func (o *ErrorObject) SetSubErrors(v []ErrorObject) {
	o.SubErrors = v
}

func (o ErrorObject) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o ErrorObject) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["code"] = o.Code
	toSerialize["message"] = o.Message
	toSerialize["field"] = o.Field
	if !IsNil(o.SubErrors) {
		toSerialize["sub_errors"] = o.SubErrors
	}

	for key, value := range o.AdditionalProperties {
		toSerialize[key] = value
	}

	return toSerialize, nil
}

func (o *ErrorObject) UnmarshalJSON(data []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"code",
		"message",
	}

	allProperties := make(map[string]interface{})

	err = json.Unmarshal(data, &allProperties)

	if err != nil {
		return err
	}

	for _, requiredProperty := range requiredProperties {
		if _, exists := allProperties[requiredProperty]; !exists {
			return fmt.Errorf("no value given for required property %v", requiredProperty)
		}
	}

	varErrorObject := _ErrorObject{}

	err = json.Unmarshal(data, &varErrorObject)

	if err != nil {
		return err
	}

	*o = ErrorObject(varErrorObject)

	additionalProperties := make(map[string]interface{})

	if err = json.Unmarshal(data, &additionalProperties); err == nil {
		delete(additionalProperties, "code")
		delete(additionalProperties, "message")
		delete(additionalProperties, "field")
		delete(additionalProperties, "sub_errors")
		o.AdditionalProperties = additionalProperties
	}

	return err
}

type NullableErrorObject struct {
	value *ErrorObject
	isSet bool
}

func (v NullableErrorObject) Get() *ErrorObject {
	return v.value
}

func (v *NullableErrorObject) Set(val *ErrorObject) {
	v.value = val
	v.isSet = true
}

func (v NullableErrorObject) IsSet() bool {
	return v.isSet
}

func (v *NullableErrorObject) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableErrorObject(val *ErrorObject) *NullableErrorObject {
	return &NullableErrorObject{value: val, isSet: true}
}

func (v NullableErrorObject) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableErrorObject) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
