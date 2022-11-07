// Copyright 2022 Nukleros
// SPDX-License-Identifier: MIT

package validate

import (
	"errors"
	"fmt"
	"os"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

const (
	ImageRegistryValidationName = "trusted-image-registry"
	ImageRegistryEnv            = "TRUSTED_IMAGE_REGISTRY"
	ImageRegistriesEnv          = "TRUSTED_IMAGE_REGISTRIES"
)

var ErrPodImageRegistry = errors.New("unable to permit pod with images from an untrusted registry")

// ImageRegistry validates whether a pod spec has a valid registry.
func ImageRegistry(validation *Validation) (bool, error) {
	trustedRegistry := os.Getenv(ImageRegistryEnv)
	trustedRegistries := os.Getenv(ImageRegistriesEnv)

	// if we do not have a trusted registry, we can skip this validation check
	if trustedRegistry == "" && trustedRegistries == "" {
		return true, nil
	}

	allTrustedRegistries := []string{}
	for _, registryList := range []string{trustedRegistry, trustedRegistries} {
		allTrustedRegistries = append(allTrustedRegistries, strings.Split(registryList, ",")...)
	}

	allContainers := []corev1.Container{}
	allContainers = append(append(allContainers, validation.PodSpec.InitContainers...), validation.PodSpec.Containers...)

	containersWithUntrustedRegistries := []corev1.Container{}

CONTAINERS:
	for c := range allContainers {
		for r := range allTrustedRegistries {
			if strings.HasPrefix(allContainers[c].Image, allTrustedRegistries[r]) {
				continue CONTAINERS
			}
		}

		containersWithUntrustedRegistries = append(containersWithUntrustedRegistries, allContainers[c])
	}

	if len(containersWithUntrustedRegistries) > 0 {
		return validation.Failed(
			fmt.Errorf("%w - container not using registry %s", ErrPodImageRegistry, trustedRegistry),
			containersWithUntrustedRegistries...,
		)
	}

	return true, nil
}
