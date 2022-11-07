// Copyright 2022 Nukleros
// SPDX-License-Identifier: MIT

//nolint:testpackage,gochecknoglobals
package validate

import (
	corev1 "k8s.io/api/core/v1"
)

var (
	truePointer  bool = true
	falsePointer bool = false

	rootUser    int64 = 0
	nonRootUser int64 = 1234
)

func defaultServiceAccountPodSpec() *corev1.PodSpec {
	return &corev1.PodSpec{
		ServiceAccountName: defaultServiceAccountName,
		Containers: []corev1.Container{
			{
				Name: defaultServiceAccountName,
			},
		},
	}
}

func emptyPodSpec() *corev1.PodSpec {
	return &corev1.PodSpec{
		Containers: []corev1.Container{{Name: "empty"}},
	}
}

func validPodSpec() *corev1.PodSpec {
	return &corev1.PodSpec{
		HostPID:     false,
		HostIPC:     false,
		HostNetwork: false,
		SecurityContext: &corev1.PodSecurityContext{
			RunAsNonRoot: &truePointer,
			RunAsUser:    &nonRootUser,
		},
		ServiceAccountName: "valid",
		Containers: []corev1.Container{
			{
				Name: "valid",
				SecurityContext: &corev1.SecurityContext{
					Privileged:               &falsePointer,
					AllowPrivilegeEscalation: &falsePointer,
					RunAsUser:                &nonRootUser,
					RunAsNonRoot:             &truePointer,
					Capabilities: &corev1.Capabilities{
						Drop: []corev1.Capability{
							"ALL",
							"NET_RAW",
						},
					},
				},
			},
			{
				Name: "valid-2",
				SecurityContext: &corev1.SecurityContext{
					Privileged:               &falsePointer,
					AllowPrivilegeEscalation: &falsePointer,
					RunAsUser:                &nonRootUser,
					RunAsNonRoot:             &truePointer,
					Capabilities: &corev1.Capabilities{
						Drop: []corev1.Capability{
							"ALL",
							"NET_RAW",
						},
					},
				},
			},
		},
	}
}

func invalidPodSpec() *corev1.PodSpec {
	return &corev1.PodSpec{
		HostPID:     true,
		HostIPC:     true,
		HostNetwork: true,
		Containers: []corev1.Container{
			{
				Name: "valid",
				SecurityContext: &corev1.SecurityContext{
					Privileged:               &falsePointer,
					AllowPrivilegeEscalation: &falsePointer,
					RunAsUser:                &nonRootUser,
					RunAsNonRoot:             &truePointer,
					Capabilities: &corev1.Capabilities{
						Drop: []corev1.Capability{
							"ALL",
							"NET_RAW",
						},
					},
				},
			},
			{
				Name: "invalid",
				SecurityContext: &corev1.SecurityContext{
					Privileged:               &truePointer,
					AllowPrivilegeEscalation: &truePointer,
					Capabilities: &corev1.Capabilities{
						Add: []corev1.Capability{
							"NET_RAW",
						},
					},
				},
			},
		},
	}
}

func validPodSpecExplicitRunAsNonRoot() *corev1.PodSpec {
	return &corev1.PodSpec{
		SecurityContext: &corev1.PodSecurityContext{
			RunAsNonRoot: &falsePointer,
			RunAsUser:    &rootUser,
		},
		Containers: []corev1.Container{
			{
				Name: "valid-explicit",
				SecurityContext: &corev1.SecurityContext{
					RunAsNonRoot: &truePointer,
					RunAsUser:    &nonRootUser,
				},
			},
		},
	}
}

func invalidPodSpecExplicitRunAsNonRoot() *corev1.PodSpec {
	return &corev1.PodSpec{
		SecurityContext: &corev1.PodSecurityContext{
			RunAsNonRoot: &truePointer,
			RunAsUser:    &rootUser,
		},
		Containers: []corev1.Container{
			{
				Name: "invalid-explicit",
				SecurityContext: &corev1.SecurityContext{
					RunAsNonRoot: &falsePointer,
				},
			},
		},
	}
}
