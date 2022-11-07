// Copyright 2022 Nukleros
// SPDX-License-Identifier: MIT

//nolint:dupl,testpackage
package validate

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestValidateHostPID(t *testing.T) {
	t.Parallel()

	type args struct {
		validation *Validation
	}

	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{
			name: "ensure a valid pod spec passes validation (hostPID = false)",
			args: args{
				validation: &Validation{
					Resource: &corev1.Pod{
						Spec: *validPodSpec(),
					},
					PodSpec: validPodSpec(),
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ensure an invalid pod spec fails validation (hostPID = true)",
			args: args{
				validation: &Validation{
					Resource: &corev1.Pod{
						Spec: *invalidPodSpec(),
					},
					PodSpec: invalidPodSpec(),
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "ensure an empty security context passes validation (hostPID = default)",
			args: args{
				validation: &Validation{
					Resource: &corev1.Pod{
						Spec: *emptyPodSpec(),
					},
					PodSpec: emptyPodSpec(),
				},
			},
			want:    true,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := HostPID(tt.args.validation)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateHostPID() error = %v, wantErr %v", err, tt.wantErr)

				return
			}
			if got != tt.want {
				t.Errorf("ValidateHostPID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateHostIPC(t *testing.T) {
	t.Parallel()

	type args struct {
		validation *Validation
	}

	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{
			name: "ensure a valid pod spec passes validation (hostIPC = false)",
			args: args{
				validation: &Validation{
					Resource: &corev1.Pod{
						Spec: *validPodSpec(),
					},
					PodSpec: validPodSpec(),
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ensure an invalid pod spec fails validation (hostIPC = true)",
			args: args{
				validation: &Validation{
					Resource: &corev1.Pod{
						Spec: *invalidPodSpec(),
					},
					PodSpec: invalidPodSpec(),
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "ensure an empty security context passes validation (hostIPC = default)",
			args: args{
				validation: &Validation{
					Resource: &corev1.Pod{
						Spec: *emptyPodSpec(),
					},
					PodSpec: emptyPodSpec(),
				},
			},
			want:    true,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := HostIPC(tt.args.validation)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateHostIPC() error = %v, wantErr %v", err, tt.wantErr)

				return
			}
			if got != tt.want {
				t.Errorf("ValidateHostIPC() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateHostNetwork(t *testing.T) {
	t.Parallel()

	type args struct {
		validation *Validation
	}

	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{
			name: "ensure a valid pod spec passes validation (hostNetwork = false)",
			args: args{
				validation: &Validation{
					Resource: &corev1.Pod{
						Spec: *validPodSpec(),
					},
					PodSpec: validPodSpec(),
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ensure an invalid pod spec fails validation (hostNetwork = true)",
			args: args{
				validation: &Validation{
					Resource: &corev1.Pod{
						Spec: *invalidPodSpec(),
					},
					PodSpec: invalidPodSpec(),
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "ensure an empty security context passes validation (hostNetwork = default)",
			args: args{
				validation: &Validation{
					Resource: &corev1.Pod{
						Spec: *emptyPodSpec(),
					},
					PodSpec: emptyPodSpec(),
				},
			},
			want:    true,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := HostNetwork(tt.args.validation)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateHostNetwork() error = %v, wantErr %v", err, tt.wantErr)

				return
			}
			if got != tt.want {
				t.Errorf("ValidateHostNetwork() = %v, want %v", got, tt.want)
			}
		})
	}
}
