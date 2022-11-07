// Copyright 2022 Nukleros
// SPDX-License-Identifier: MIT

//nolint:dupl,testpackage
package validate

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestValidateDefaultServiceAccount(t *testing.T) {
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
			name: "ensure a valid pod spec passes validation (serviceAccountName = valid)",
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
			name: "ensure an invalid pod spec fails validation (serviceAccountName = empty)",
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
			name: "ensure an invalid pod spec fails validation (serviceAccountName = default)",
			args: args{
				validation: &Validation{
					Resource: &corev1.Pod{
						Spec: *defaultServiceAccountPodSpec(),
					},
					PodSpec: defaultServiceAccountPodSpec(),
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
			got, err := DefaultServiceAccount(tt.args.validation)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateDefaultServiceAccount() error = %v, wantErr %v", err, tt.wantErr)

				return
			}
			if got != tt.want {
				t.Errorf("ValidateDefaultServiceAccount() = %v, want %v", got, tt.want)
			}
		})
	}
}
