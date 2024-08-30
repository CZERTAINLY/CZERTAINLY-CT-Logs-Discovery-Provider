package sslmate

import (
	"encoding/json"
	"fmt"
)

// checks if the IssuerObject type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &IssuerObject{}

type IssuerObject struct {
	// The organization which issued the certificate. This name is curated by SSLMate to be an accurate and helpful
	// way to identify the issuer of a certificate, so we recommend you use it instead of the certificate's
	// Issuer Distinguished Name
	FriendlyName string `json:"friendly_name"`
	// The domain names which can be placed in a CAA record to authorize the issuer.
	CaaDomains           []string `json:"caa_domains,omitempty"`
	AdditionalProperties map[string]interface{}
}

type _IssuerObject IssuerObject

func NewIssuerObject(friendlyName string, caaDomains []string) *IssuerObject {
	this := IssuerObject{}
	this.FriendlyName = friendlyName
	this.CaaDomains = caaDomains
	return &this
}

func NewIssuerObjectWithDefaults() *IssuerObject {
	this := IssuerObject{}
	return &this
}

func (o *IssuerObject) GetFriendlyName() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.FriendlyName
}

func (o *IssuerObject) GetFriendlyNameOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.FriendlyName, true
}

func (o *IssuerObject) SetFriendlyName(v string) {
	o.FriendlyName = v
}

func (o *IssuerObject) GetCaaDomains() []string {
	if o == nil {
		var ret []string
		return ret
	}

	return o.CaaDomains
}

func (o *IssuerObject) GetCaaDomainsOk() (*[]string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.CaaDomains, true
}

func (o *IssuerObject) SetCaaDomains(v []string) {
	o.CaaDomains = v
}

func (o IssuerObject) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o IssuerObject) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["friendly_name"] = o.FriendlyName
	toSerialize["caa_domains"] = o.CaaDomains

	for key, value := range o.AdditionalProperties {
		toSerialize[key] = value
	}

	return toSerialize, nil
}

func (o *IssuerObject) UnmarshalJSON(data []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"friendly_name",
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

	varIssuerObject := _IssuerObject{}

	err = json.Unmarshal(data, &varIssuerObject)

	if err != nil {
		return err
	}

	*o = IssuerObject(varIssuerObject)

	additionalProperties := make(map[string]interface{})

	if err = json.Unmarshal(data, &additionalProperties); err == nil {
		delete(additionalProperties, "friendly_name")
		delete(additionalProperties, "caa_domains")
		o.AdditionalProperties = additionalProperties
	}

	return err
}

type NullableIssuerObject struct {
	value *IssuerObject
	isSet bool
}

func (v NullableIssuerObject) Get() *IssuerObject {
	return v.value
}

func (v *NullableIssuerObject) Set(val *IssuerObject) {
	v.value = val
	v.isSet = true
}

func (v NullableIssuerObject) IsSet() bool {
	return v.isSet
}

func (v *NullableIssuerObject) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableIssuerObject(val *IssuerObject) *NullableIssuerObject {
	return &NullableIssuerObject{value: val, isSet: true}
}

func (v NullableIssuerObject) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableIssuerObject) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
