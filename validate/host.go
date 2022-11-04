// Copyright 2022 Nukleros
// SPDX-License-Identifier: MIT

package validate

import "errors"

const (
	ValidateHostPIDName     = "host-pid"
	ValidateHostIPCName     = "host-ipc"
	ValidateHostNetworkName = "host-network"
)

var (
	ErrPodHostPID     = errors.New("unable to permit pod with hostPID")
	ErrPodHostIPC     = errors.New("unable to permit pod with hostIPC")
	ErrPodHostNetwork = errors.New("unable to permit pod with hostNetwork")
)

// ValidateHostPID validates whether a pod spec has the hostPID value set.
func ValidateHostPID(validation *Validation) (bool, error) {
	if validation.PodSpec.HostPID {
		return validation.Failed(ErrPodHostPID)
	}

	return true, nil
}

// ValidateHostIPC validates whether a pod spec has the hostIPC value set.
func ValidateHostIPC(validation *Validation) (bool, error) {
	if validation.PodSpec.HostIPC {
		return validation.Failed(ErrPodHostIPC)
	}

	return true, nil
}

// ValidateHostNetwork validates whether a pod is rquesting binding to the
// host network.
func ValidateHostNetwork(validation *Validation) (bool, error) {
	if validation.PodSpec.HostNetwork {
		return validation.Failed(ErrPodHostNetwork)
	}

	return true, nil
}
