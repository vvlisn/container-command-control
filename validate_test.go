package main

import (
	"encoding/json"
	"testing"

	kubewarden_protocol "github.com/kubewarden/policy-sdk-go/protocol"
)

func TestValidateDeployment(t *testing.T) {
	tests := []struct {
		name        string
		settings    string
		deployment  string
		shouldAllow bool
	}{
		{
			name: "Default deny - No args and command",
			settings: `{
                "allow_args_and_command": false
            }`,
			deployment: `{
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "spec": {
                    "template": {
                        "spec": {
                            "containers": [
                                {
                                    "name": "test-container",
                                    "image": "nginx:latest"
                                }
                            ]
                        }
                    }
                }
            }`,
			shouldAllow: true,
		},
		{
			name: "Default deny - Has args",
			settings: `{
                "allow_args_and_command": false
            }`,
			deployment: `{
                "apiVersion": "apps/v1",
                "kind": "Deployment", 
                "spec": {
                    "template": {
                        "spec": {
                            "containers": [
                                {
                                    "name": "test-container",
                                    "image": "nginx:latest",
                                    "args": ["--port=8080"]
                                }
                            ]
                        }
                    }
                }
            }`,
			shouldAllow: false,
		},
		{
			name: "Allow configuration - Has command and args",
			settings: `{
                "allow_args_and_command": true
            }`,
			deployment: `{
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "spec": {
                    "template": {
                        "spec": {
                            "containers": [
                                {
                                    "name": "test-container",
                                    "image": "nginx:latest",
                                    "command": ["/bin/sh"],
                                    "args": ["-c", "nginx -g 'daemon off;'"]
                                }
                            ]
                        }
                    }
                }
            }`,
			shouldAllow: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			request := kubewarden_protocol.ValidationRequest{
				Request: kubewarden_protocol.KubernetesAdmissionRequest{
					Object: json.RawMessage(tc.deployment),
					Kind: kubewarden_protocol.GroupVersionKind{
						Kind: "Deployment",
					},
				},
				Settings: json.RawMessage(tc.settings),
			}

			payload, err := json.Marshal(request)
			if err != nil {
				t.Errorf("Failed to build validation request: %v", err)
			}

			responsePayload, err := validate(payload)
			if err != nil {
				t.Errorf("Failed to execute validation: %v", err)
			}

			var response kubewarden_protocol.ValidationResponse
			if unmarshalErr := json.Unmarshal(responsePayload, &response); unmarshalErr != nil {
				t.Errorf("Failed to parse response: %v", unmarshalErr)
			}

			if response.Accepted != tc.shouldAllow {
				t.Errorf("Validation result does not match: expected %v, got %v. Message: %s",
					tc.shouldAllow, response.Accepted, *response.Message)
			}
		})
	}
}
