// Copyright 2022 Nukleros
// SPDX-License-Identifier: MIT

package validate

import "errors"

const (
	HostPIDValidationName     = "host-pid"
	HostIPCValidationName     = "host-ipc"
	HostNetworkValidationName = "host-network"
)

var (
	ErrPodHostPID     = errors.New("unable to permit pod with hostPID")
	ErrPodHostIPC     = errors.New("unable to permit pod with hostIPC")
	ErrPodHostNetwork = errors.New("unable to permit pod with hostNetwork")
)

// HostPID validates whether a pod spec has the hostPID value set.
func HostPID(validation *Validation) (bool, error) {
	if validation.PodSpec.HostPID {
		return validation.Failed(ErrPodHostPID)
	}

	return true, nil
}

// HostIPC validates whether a pod spec has the hostIPC value set.
func HostIPC(validation *Validation) (bool, error) {
	if validation.PodSpec.HostIPC {
		return validation.Failed(ErrPodHostIPC)
	}

	return true, nil
}

// HostNetwork validates whether a pod is rquesting binding to the
// host network.
func HostNetwork(validation *Validation) (bool, error) {
	if validation.PodSpec.HostNetwork {
		return validation.Failed(ErrPodHostNetwork)
	}

	return true, nil
}
