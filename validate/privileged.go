// Copyright 2022 Nukleros
// SPDX-License-Identifier: MIT

package validate

import (
	"errors"

	corev1 "k8s.io/api/core/v1"

	"github.com/nukleros/pod-security-webhook/resources"
)

const (
	ValidateRunAsNonRootName             = "run-as-non-root"
	ValidatePrivilegedName               = "privileged-container"
	ValidateAllowPrivilegeEscalationName = "privilege-escalation-container"
)

var (
	ErrPodRunAsNonRoot          = errors.New("unable to permit pod attempting to run as root")
	ErrContainerPrivileged      = errors.New("unable to permit privileged container")
	ErrContainerAllowPrivileged = errors.New("unable to permit container which allows privileged escalation")
)

// ValidateRunAsNonRoot validates whether a container or pod is set to enforce running as a non-root user.
func ValidateRunAsNonRoot(validation *Validation) (bool, error) {
	containersAsRoot := []corev1.Container{}

	for _, container := range validation.PodSpec.Containers {
		runAsUser := resources.EffectiveRunAsUser(validation.PodSpec.SecurityContext, container.SecurityContext)
		if runAsUser != nil && *runAsUser > 0 {
			continue
		}

		runAsNonRoot := resources.EffectiveRunAsNonRoot(validation.PodSpec.SecurityContext, container.SecurityContext)
		if runAsNonRoot {
			if runAsUser != nil && *runAsUser == 0 {
				containersAsRoot = append(containersAsRoot, container)
			}

			continue
		}

		containersAsRoot = append(containersAsRoot, container)
	}

	if len(containersAsRoot) == 0 {
		return true, nil
	}

	return validation.Failed(ErrPodRunAsNonRoot, containersAsRoot...)
}

// ValidatePrivileged validates whether a pod spec has the privileged value set.
func ValidatePrivileged(validation *Validation) (bool, error) {
	containersWithPrivileged := []corev1.Container{}

	for _, container := range validation.PodSpec.Containers {
		if resources.GetSecurityContext(container).Privileged == nil {
			continue
		}

		if *container.SecurityContext.Privileged {
			containersWithPrivileged = append(containersWithPrivileged, container)
		}
	}

	if len(containersWithPrivileged) == 0 {
		return true, nil
	}

	return validation.Failed(ErrContainerPrivileged, containersWithPrivileged...)
}

// ValidateAllowPrivilegeEscalation validates whether a container is allowing
// privilege escalation.
func ValidateAllowPrivilegeEscalation(validation *Validation) (bool, error) {
	containersWithPrivileged := []corev1.Container{}

	for _, container := range validation.PodSpec.Containers {
		if resources.GetSecurityContext(container).AllowPrivilegeEscalation == nil {
			continue
		}

		if *container.SecurityContext.AllowPrivilegeEscalation {
			containersWithPrivileged = append(containersWithPrivileged, container)
		}
	}

	if len(containersWithPrivileged) == 0 {
		return true, nil
	}

	return validation.Failed(ErrContainerAllowPrivileged, containersWithPrivileged...)
}
