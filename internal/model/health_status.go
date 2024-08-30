package model

import (
	"fmt"
)

// HealthStatus : Current connector operational status
type HealthStatus string

// List of HealthStatus
const (
	OK      HealthStatus = "ok"
	NOK     HealthStatus = "nok"
	UNKNOWN HealthStatus = "unknown"
)

// AllowedHealthStatusEnumValues is all the allowed values of HealthStatus enum
var AllowedHealthStatusEnumValues = []HealthStatus{
	"ok",
	"nok",
	"unknown",
}

// validHealthStatusEnumValue provides a map of HealthStatuss for fast verification of use input
var validHealthStatusEnumValues = map[HealthStatus]struct{}{
	"ok":      {},
	"nok":     {},
	"unknown": {},
}

// IsValid return true if the value is valid for the enum, false otherwise
func (v HealthStatus) IsValid() bool {
	_, ok := validHealthStatusEnumValues[v]
	return ok
}

// NewHealthStatusFromValue returns a pointer to a valid HealthStatus
// for the value passed as argument, or an error if the value passed is not allowed by the enum
func NewHealthStatusFromValue(v string) (HealthStatus, error) {
	ev := HealthStatus(v)
	if ev.IsValid() {
		return ev, nil
	} else {
		return "", fmt.Errorf("invalid value '%v' for HealthStatus: valid values are %v", v, AllowedHealthStatusEnumValues)
	}
}

// AssertHealthStatusRequired checks if the required fields are not zero-ed
func AssertHealthStatusRequired(obj HealthStatus) error {
	return nil
}

// AssertHealthStatusConstraints checks if the values respects the defined constraints
func AssertHealthStatusConstraints(obj HealthStatus) error {
	return nil
}
