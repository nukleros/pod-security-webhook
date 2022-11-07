// Copyright 2022 Nukleros
// SPDX-License-Identifier: MIT

package validate

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestValidateRunAsNonRoot(t *testing.T) {
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
			name: "ensure a valid pod spec passes validation (runAsNonRoot = true)",
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
			name: "ensure an invalid pod spec fails validation (runAsNonRoot = false)",
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
			name: "ensure an empty security context false validation (runAsNonRoot = default)",
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
		{
			name: "ensure an explicit override of pod security context fails validation (runAsNonRoot = false)",
			args: args{
				validation: &Validation{
					Resource: &corev1.Pod{
						Spec: *invalidPodSpecExplicitRunAsNonRoot(),
					},
					PodSpec: invalidPodSpecExplicitRunAsNonRoot(),
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "ensure an explicit override of pod security context passes validation (runAsNonRoot = true)",
			args: args{
				validation: &Validation{
					Resource: &corev1.Pod{
						Spec: *validPodSpecExplicitRunAsNonRoot(),
					},
					PodSpec: validPodSpecExplicitRunAsNonRoot(),
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
			got, err := RunAsNonRoot(tt.args.validation)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateRunAsNonRoot() error = %v, wantErr %v", err, tt.wantErr)

				return
			}
			if got != tt.want {
				t.Errorf("ValidateRunAsNonRoot() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidatePrivileged(t *testing.T) {
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
			name: "ensure a valid security context passes validation (privileged = false)",
			args: args{
				validation: &Validation{
					PodSpec: validPodSpec(),
					Resource: &corev1.Pod{
						Spec: *validPodSpec(),
					},
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ensure an invalid security context fails validation (privileged = true)",
			args: args{
				validation: &Validation{
					PodSpec: invalidPodSpec(),
					Resource: &corev1.Pod{
						Spec: *invalidPodSpec(),
					},
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "ensure an empty security context passes validation (privileged = default)",
			args: args{
				validation: &Validation{
					PodSpec: emptyPodSpec(),
					Resource: &corev1.Pod{
						Spec: *emptyPodSpec(),
					},
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
			got, err := Privileged(tt.args.validation)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePrivileged() error = %v, wantErr %v", err, tt.wantErr)

				return
			}
			if got != tt.want {
				t.Errorf("ValidatePrivileged() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateAllowPrivilegeEscalation(t *testing.T) {
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
			name: "ensure a valid security context passes validation (allowPrivilegeEscalation = false)",
			args: args{
				validation: &Validation{
					PodSpec: validPodSpec(),
					Resource: &corev1.Pod{
						Spec: *validPodSpec(),
					},
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "ensure an invalid security context fails validation (allowPrivilegeEscalation = true)",
			args: args{
				validation: &Validation{
					PodSpec: invalidPodSpec(),
					Resource: &corev1.Pod{
						Spec: *invalidPodSpec(),
					},
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "ensure an empty security context passes validation (allowPrivilegeEscalation = default)",
			args: args{
				validation: &Validation{
					PodSpec: emptyPodSpec(),
					Resource: &corev1.Pod{
						Spec: *emptyPodSpec(),
					},
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
			got, err := AllowPrivilegeEscalation(tt.args.validation)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateAllowPrivilegeEscalation() error = %v, wantErr %v", err, tt.wantErr)

				return
			}
			if got != tt.want {
				t.Errorf("ValidateAllowPrivilegeEscalation() = %v, want %v", got, tt.want)
			}
		})
	}
}
