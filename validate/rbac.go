// Copyright 2022 Nukleros
// SPDX-License-Identifier: MIT

package validate

import (
	"errors"
)

const (
	defaultServiceAccountName = "default"

	ValidateDefaultServiceAccountName = "default-service-account"
)

var (
	ErrPodDefaultServiceAccount = errors.New("unable to permit pod attempting to use the default service account")
	ErrPodMissingServiceAccount = errors.New("unable to permit pod attempting to use empty service account")
)

// ValidateDefaultServiceAccount validates whether a pod is attempting to launch with the namespace
// default service account.
func ValidateDefaultServiceAccount(validation *Validation) (bool, error) {
	if validation.PodSpec.ServiceAccountName == "" {
		return validation.Failed(ErrPodMissingServiceAccount)
	}

	if validation.PodSpec.ServiceAccountName == defaultServiceAccountName {
		return validation.Failed(ErrPodDefaultServiceAccount)
	}

	return true, nil
}
