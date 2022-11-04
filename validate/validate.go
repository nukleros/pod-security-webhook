// Copyright 2022 Nukleros
// SPDX-License-Identifier: MIT

package validate

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/nukleros/pod-security-webhook/resources"
)

const SkipValidationEnvValue = "false"

type Validation struct {
	Name     string
	Resource client.Object
	PodSpec  *corev1.PodSpec
	Run      ValidationLogic
	Skip     bool
}

type ValidationLogic func(*Validation) (bool, error)

// NewValidation return an instance of a new validation.
func NewValidation(name string, validateLogic ValidationLogic) *Validation {
	return &Validation{
		Name: name,
		Run:  validateLogic,
	}
}

// Execute executes the validation logic.
func (validation *Validation) Execute() (bool, error) {
	return validation.Run(validation)
}

// Failed returns the error message for a failed validation and a false boolean to
// indicate that the validation logic has failed for a ValidationLogic function.
func (validation *Validation) Failed(parentErr error, failedContainers ...corev1.Container) (bool, error) {
	if len(failedContainers) > 0 {
		return false, fmt.Errorf(
			"failed validation %s for %s - %s for containers %s",
			validation.Name,
			strings.ToLower(resources.ToString(validation.Resource)),
			parentErr,
			resources.GetContainerNames(failedContainers),
		)
	}

	return false, fmt.Errorf(
		"failed validation %s for %s - %s",
		validation.Name,
		strings.ToLower(resources.ToString(validation.Resource)),
		parentErr,
	)
}

// EnvironmetVariableOverride returns the expected environment variable override given the
// name of the validation.
func (validation *Validation) EnvironmetVariableOverride() string {
	// replace dashes with underscores
	envVar := strings.ReplaceAll(validation.Name, "-", "_")

	return fmt.Sprintf("VALIDATE_%s", strings.ToUpper(envVar))
}

// AnnotationOverride returns the expected annotation variable override given the
// name of the validation.
func (validation *Validation) AnnotationOverride() string {
	if alias := annotationAliasFor(validation.Name); alias != "" {
		return fmt.Sprintf("ignore-check.kube-linter.io/%s", alias)
	}

	return fmt.Sprintf("ignore-check.kube-linter.io/%s", validation.Name)
}

// annotationAliasFor is a list of aliases that link back to proper kube-linter aliases.  This
// allows for the annotations that overlap to keep the same linter name, but have different
// validation names.  The annotation name is reeturned from the list to be used as the
// annotation override value.
func annotationAliasFor(name string) string {
	return map[string]string{
		"verify-drop-container-capabilities": "verify-container-capabilities",
		"verify-add-container-capabilities":  "verify-container-capabilities",
	}[name]
}
