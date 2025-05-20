package main

import (
	"encoding/json"
	"fmt"

	kubewarden "github.com/kubewarden/policy-sdk-go"
	kubewarden_protocol "github.com/kubewarden/policy-sdk-go/protocol"
)

// Settings describes the policy settings.
type Settings struct {
	AllowArgsAndCommand bool `json:"allow_args_and_command"`
}

// NewSettingsFromValidationReq creates a Settings instance from ValidationRequest.
func NewSettingsFromValidationReq(validationReq *kubewarden_protocol.ValidationRequest) (Settings, error) {
	settings := Settings{}
	if validationReq.Settings != nil {
		err := json.Unmarshal(validationReq.Settings, &settings)
		if err != nil {
			return Settings{}, err
		}
	}
	return settings, nil
}

// Valid validates if the settings are valid.
func (s *Settings) Valid() (bool, error) {
	return true, nil
}

func validateSettings(payload []byte) ([]byte, error) {
	settings := Settings{}
	err := json.Unmarshal(payload, &settings)
	if err != nil {
		return kubewarden.RejectSettings(
			kubewarden.Message(fmt.Sprintf("Invalid settings: %v", err)))
	}
	return kubewarden.AcceptSettings()
}
