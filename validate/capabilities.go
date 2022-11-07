// Copyright 2022 Nukleros
// SPDX-License-Identifier: MIT

package validate

import (
	"errors"

	corev1 "k8s.io/api/core/v1"

	"github.com/nukleros/pod-security-webhook/resources"
)

const (
	AddCapabilitiesValidationName  = "verify-add-container-capabilities"
	DropCapabilitiesValidationName = "verify-drop-container-capabilities"
)

var (
	ErrContainerRequestAddCapabilities  = errors.New("unable to permit container adding escalated capabilities")
	ErrContainerMissingDropCapabilities = errors.New("unable to permit container missing either drop capabilities of ALL or NET_RAW")
)

// AddCapabilities validates whether a pod spec has the appropriate drop capabilities set.
func AddCapabilities(validation *Validation) (bool, error) {
	containersRequestingAddCapabilities := []corev1.Container{}

	for i := range validation.PodSpec.Containers {
		container := validation.PodSpec.Containers[i]

		securityContext := resources.GetSecurityContext(container)

		if securityContext.Capabilities != nil {
			if securityContext.Capabilities.Add != nil {
				if len(securityContext.Capabilities.Add) > 0 {
					containersRequestingAddCapabilities = append(containersRequestingAddCapabilities, container)
				}
			}
		}
	}

	if len(containersRequestingAddCapabilities) == 0 {
		return true, nil
	}

	return validation.Failed(ErrContainerRequestAddCapabilities, containersRequestingAddCapabilities...)
}

// DropCapabilities validates whether a pod spec has the appropriate drop capabilities set.
func DropCapabilities(validation *Validation) (bool, error) {
	containersMissingDropCapabilities := []corev1.Container{}

	for i := range validation.PodSpec.Containers {
		container := validation.PodSpec.Containers[i]

		securityContext := resources.GetSecurityContext(container)

		if securityContext.Capabilities != nil {
			if securityContext.Capabilities.Drop != nil {
				if len(securityContext.Capabilities.Drop) > 0 {
					if resources.HasRequiredCapability(securityContext.Capabilities.Drop, "all", "new_raw") {
						continue
					}
				}
			}
		}

		containersMissingDropCapabilities = append(containersMissingDropCapabilities, container)
	}

	if len(containersMissingDropCapabilities) == 0 {
		return true, nil
	}

	return validation.Failed(ErrContainerMissingDropCapabilities, containersMissingDropCapabilities...)
}
