// Copyright 2022 Nukleros
// SPDX-License-Identifier: MIT

package webhook

import (
	"fmt"
	"net/http"
	"os"

	"github.com/nukleros/pod-security-webhook/resources"
	"github.com/nukleros/pod-security-webhook/validate"
)

var (
	ErrValidationFailed = "failed validation"
)

// validate runs through each step of the validation process.
func (webhook *Webhook) validate(w http.ResponseWriter, r *http.Request) {
	// create a new operation object for each instance of mutate
	operation := &Operation{
		Log: webhook.Log,
		OperationStep: []OperationStep{
			webhook.performSetup,
			webhook.performValidate,
		},
	}

	// set the register function to register the operations
	operation.RegisterFunc = operation.registerValidations

	// run the operation
	operation.run(webhook, w, r)
}

// registerValidations registers all validations that are know to this webhook.
func (operation *Operation) registerValidations() {
	// validate no privilege escalation requests and no root containers unless overridden by an annotation or environment
	// variable
	operation.registerValidation(validate.NewValidation(validate.RunAsNonRootValidationName, validate.RunAsNonRoot))
	operation.registerValidation(validate.NewValidation(validate.PrivilegedValidationName, validate.Privileged))
	operation.registerValidation(validate.NewValidation(validate.AllowPrivilegeEscalationValidationName, validate.AllowPrivilegeEscalation))

	// validate items pertaining access to host resources
	operation.registerValidation(validate.NewValidation(validate.HostPIDValidationName, validate.HostPID))
	operation.registerValidation(validate.NewValidation(validate.HostIPCValidationName, validate.HostIPC))
	operation.registerValidation(validate.NewValidation(validate.HostNetworkValidationName, validate.HostNetwork))

	// validate items pertaining to expanded container capabilities
	operation.registerValidation(validate.NewValidation(validate.AddCapabilitiesValidationName, validate.AddCapabilities))
	operation.registerValidation(validate.NewValidation(validate.DropCapabilitiesValidationName, validate.DropCapabilities))

	// validate items pertaining to images
	operation.registerValidation(validate.NewValidation(validate.ImageRegistryValidationName, validate.ImageRegistry))
}

// registerValidation registers an individual valiation for the webhook.
func (operation *Operation) registerValidation(validation *validate.Validation) {
	// do not register a validation if we have an environment variable override set explicitly to 'false'
	if os.Getenv(validation.EnvironmetVariableOverride()) == validate.SkipValidationEnvValue {
		operation.Log.Infof(
			"skipping validation [%s] due to env var [%s=%s]",
			validation.Name,
			validation.EnvironmetVariableOverride(),
			validate.SkipValidationEnvValue,
		)

		return
	}

	// add the pod spec and resource to the mutation from the webhook operation
	validation.PodSpec = operation.PodSpec
	validation.Resource = operation.Resource

	// if we have owner references, we have another controller that is managing our thing
	// so we should not mutate it
	if resources.SkipViaOwnerReferences(validation.Resource) {
		// debug here otherwise each pod created by a deployment/etc will cause a log
		// message which is super chatty
		operation.Log.DebugF(
			"skipping validation [%s] due to owner references [%+v]",
			validation.Name,
			validation.Resource.GetOwnerReferences(),
		)

		return
	}

	// if we have an annotation for this resource that matches an override annotation
	// we should skip it
	if resources.SkipViaAnnotations(validation.Resource, validation.AnnotationOverride()) {
		operation.Log.Infof(
			"skipping validation [%s] due to annotation [%s=%s]",
			validation.Name,
			validation.AnnotationOverride(),
			resources.GetAnnotation(validation.Resource, validation.AnnotationOverride()),
		)

		return
	}

	operation.Log.DebugF("registering validation: %s", validation.Name)
	operation.Validations = append(operation.Validations, validation)
}

// performValidate performs prevalidation prior to actually running the tests to ensure that we
// have a clean input.
func (webhook *Webhook) performValidate(w http.ResponseWriter, r *http.Request, operation *Operation) (error, int) {
	for _, validation := range operation.Validations {
		operation.Log.DebugF("performing validation: %s", validation.Name)

		isValid, err := validation.Execute()
		if !isValid || err != nil {
			return fmt.Errorf("%s - %w", ErrValidationFailed, err), http.StatusForbidden
		}

		operation.Log.DebugF("successfully completed validation: %s", validation.Name)
	}

	return nil, http.StatusAccepted
}
