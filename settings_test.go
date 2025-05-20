package main

import (
	"encoding/json"
	"testing"

	kubewarden_protocol "github.com/kubewarden/policy-sdk-go/protocol"
)

func TestParseValidSettings(t *testing.T) {
	settingsJSON := []byte(`{
        "allow_args_and_command": true
    }`)

	settings := Settings{}
	err := json.Unmarshal(settingsJSON, &settings)
	if err != nil {
		t.Errorf("Failed to parse settings: %+v", err)
	}

	if !settings.AllowArgsAndCommand {
		t.Error("Expected AllowArgsAndCommand to be true")
	}
}

func TestValidateSettings(t *testing.T) {
	cases := []struct {
		name     string
		settings string
		isValid  bool
	}{
		{
			name: "Valid settings - Allow configuration",
			settings: `{
                "allow_args_and_command": true
            }`,
			isValid: true,
		},
		{
			name: "Valid settings - Deny configuration",
			settings: `{
                "allow_args_and_command": false
            }`,
			isValid: true,
		},
		{
			name:     "Default settings - Empty JSON",
			settings: `{}`,
			isValid:  true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			responsePayload, err := validateSettings([]byte(tc.settings))
			if err != nil {
				t.Errorf("Failed to validate settings: %+v", err)
			}

			var response kubewarden_protocol.SettingsValidationResponse
			if unmarshalErr := json.Unmarshal(responsePayload, &response); unmarshalErr != nil {
				t.Errorf("Failed to parse response: %+v", unmarshalErr)
			}

			if response.Valid != tc.isValid {
				t.Errorf("Validation result does not match: expected %v, got %v. Message: %s",
					tc.isValid, response.Valid, *response.Message)
			}
		})
	}
}

func TestInvalidSettingsFormat(t *testing.T) {
	settingsJSON := []byte(`{
        "allow_args_and_command": "invalid"
    }`)

	responsePayload, err := validateSettings(settingsJSON)
	if err != nil {
		t.Errorf("Failed to validate settings: %+v", err)
	}

	var response kubewarden_protocol.SettingsValidationResponse
	if unmarshalErr := json.Unmarshal(responsePayload, &response); unmarshalErr != nil {
		t.Errorf("Failed to parse response: %+v", unmarshalErr)
	}

	if response.Valid {
		t.Error("Should return validation failure for invalid settings format")
	}
}
