package main

import (
	"encoding/json"
	"fmt"

	kubewarden "github.com/kubewarden/policy-sdk-go"
	kubewarden_protocol "github.com/kubewarden/policy-sdk-go/protocol"
	"github.com/tidwall/gjson"
)

const (
	httpBadRequestStatusCode = 400
)

func validate(payload []byte) ([]byte, error) {
	// Create ValidationRequest instance from payload
	validationRequest := kubewarden_protocol.ValidationRequest{}
	err := json.Unmarshal(payload, &validationRequest)
	if err != nil {
		logger.ErrorWith("Failed to parse validation request").Err("error", err).Write()
		return kubewarden.RejectRequest(
			kubewarden.Message(err.Error()),
			kubewarden.Code(httpBadRequestStatusCode))
	}

	// Create Settings instance from ValidationRequest object
	settings, err := NewSettingsFromValidationReq(&validationRequest)
	if err != nil {
		logger.ErrorWith("Failed to parse policy settings").Err("error", err).Write()
		return kubewarden.RejectRequest(
			kubewarden.Message(err.Error()),
			kubewarden.Code(httpBadRequestStatusCode))
	}

	// Check if resource type is Deployment
	kind := validationRequest.Request.Kind.Kind
	if kind != "Deployment" {
		logger.InfoWith("Skipping non-Deployment resource validation").
			String("kind", kind).
			Write()
		return kubewarden.AcceptRequest()
	}

	// Get Deployment JSON data
	deploymentJSON := validationRequest.Request.Object

	logger.DebugWith("Validating Deployment Pod template parameters").
		String("operation", validationRequest.Request.Operation).
		String("kind", kind).
		Write()

	// Check containers in pod template
	containers := gjson.GetBytes(deploymentJSON, "spec.template.spec.containers")
	if containers.Exists() {
		if validateErr := validateContainers(containers, &settings); validateErr != nil {
			return kubewarden.RejectRequest(
				kubewarden.Message(validateErr.Error()),
				kubewarden.NoCode)
		}
	}

	logger.Info("Deployment Pod template validation passed")
	return kubewarden.AcceptRequest()
}

func validateContainers(containers gjson.Result, settings *Settings) error {
	// If args and command are allowed, return nil directly
	if settings.AllowArgsAndCommand {
		return nil
	}

	var err error
	containers.ForEach(func(_, container gjson.Result) bool {
		// Get container name for logging
		containerName := container.Get("name").String()

		// Check command first
		if command := container.Get("command"); command.Exists() {
			err = fmt.Errorf("command configuration is not allowed in container '%s'", containerName)
			return false
		}

		// Check args second
		if args := container.Get("args"); args.Exists() {
			err = fmt.Errorf("args configuration is not allowed in container '%s'", containerName)
			return false
		}

		return true
	})
	return err
}
