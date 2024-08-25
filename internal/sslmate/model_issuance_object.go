package sslmate

import (
	"encoding/json"
	"fmt"
)

// checks if the IssuanceObject type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &IssuanceObject{}

type IssuanceObject struct {
	// An opaque string which uniquely identifies this issuance object.
	Id string `json:"id"`
	// The base64 representation of the DER-encoded X.509 certificate (if known) or precertificate
	// (if certificate is not known). Only present if expanded.
	CertDer              string `json:"cert_der"`
	AdditionalProperties map[string]interface{}
}

type _IssuanceObject IssuanceObject

func NewIssuanceObject(id string, certDer string) *IssuanceObject {
	this := IssuanceObject{}
	this.Id = id
	this.CertDer = certDer
	return &this
}

func NewIssuanceObjectWithDefaults() *IssuanceObject {
	this := IssuanceObject{}
	return &this
}

func (o *IssuanceObject) GetId() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Id
}

func (o *IssuanceObject) GetIdOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Id, true
}

func (o *IssuanceObject) SetId(v string) {
	o.Id = v
}

func (o *IssuanceObject) GetCertDer() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.CertDer
}

func (o *IssuanceObject) GetCertDerOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.CertDer, true
}

func (o *IssuanceObject) SetCertDer(v string) {
	o.CertDer = v
}

func (o IssuanceObject) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o IssuanceObject) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["id"] = o.Id
	toSerialize["cert_der"] = o.CertDer

	for key, value := range o.AdditionalProperties {
		toSerialize[key] = value
	}

	return toSerialize, nil
}

func (o *IssuanceObject) UnmarshalJSON(data []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"id",
		"cert_der",
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

	varCertificateDetailDto := _IssuanceObject{}

	err = json.Unmarshal(data, &varCertificateDetailDto)

	if err != nil {
		return err
	}

	*o = IssuanceObject(varCertificateDetailDto)

	additionalProperties := make(map[string]interface{})

	if err = json.Unmarshal(data, &additionalProperties); err == nil {
		delete(additionalProperties, "id")
		delete(additionalProperties, "cert_der")
		o.AdditionalProperties = additionalProperties
	}

	return err
}

type NullableIssuanceObject struct {
	value *IssuanceObject
	isSet bool
}

func (v NullableIssuanceObject) Get() *IssuanceObject {
	return v.value
}

func (v *NullableIssuanceObject) Set(val *IssuanceObject) {
	v.value = val
	v.isSet = true
}

func (v NullableIssuanceObject) IsSet() bool {
	return v.isSet
}

func (v *NullableIssuanceObject) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableIssuanceObject(val *IssuanceObject) *NullableIssuanceObject {
	return &NullableIssuanceObject{value: val, isSet: true}
}

func (v NullableIssuanceObject) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableIssuanceObject) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
