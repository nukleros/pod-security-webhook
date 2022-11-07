// Copyright 2022 Nukleros
// SPDX-License-Identifier: MIT

package validate

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestValidateAddCapabilities(t *testing.T) {
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
			name: "ensure a valid pod spec passes validation (capabilites.add = empty)",
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
			name: "ensure an invalid pod spec fails validation (capabilities.add = non-empty)",
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
			name: "ensure an empty security context passes validation (capabilities.add = default)",
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
			got, err := AddCapabilities(tt.args.validation)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateAddCapabilities() error = %v, wantErr %v", err, tt.wantErr)

				return
			}
			if got != tt.want {
				t.Errorf("ValidateAddCapabilities() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateDropCapabilities(t *testing.T) {
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
			name: "ensure a valid pod spec passes validation (capabilites.drop = all or net_raw)",
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
			name: "ensure an invalid pod spec fails validation (capabilities.drop = empty)",
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
			name: "ensure an empty security context passes validation (capabilities.drop = default)",
			args: args{
				validation: &Validation{
					Resource: &corev1.Pod{
						Spec: *emptyPodSpec(),
					},
					PodSpec: emptyPodSpec(),
				},
			},
			want:    false,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := DropCapabilities(tt.args.validation)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateDropCapabilities() error = %v, wantErr %v", err, tt.wantErr)

				return
			}
			if got != tt.want {
				t.Errorf("ValidateDropCapabilities() = %v, want %v", got, tt.want)
			}
		})
	}
}
