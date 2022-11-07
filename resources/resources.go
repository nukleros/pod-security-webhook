// Copyright 2022 Nukleros
// SPDX-License-Identifier: MIT

package resources

import (
	"errors"
	"fmt"
	"strings"

	"github.com/nukleros/operator-builder-tools/pkg/resources"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	ErrValidatingKind = errors.New("error validating kind")
)

// GetPodSpec returns the pod specification for a given set of objects.
//nolint:cyclop
// TODO: we can improve the massive case statement logic.
func GetPodSpec(resource client.Object) (*corev1.PodSpec, error) {
	// we only want to validate application types
	switch resource.GetObjectKind().GroupVersionKind().Kind {
	//nolint:goconst
	case "Pod":
		pod := &corev1.Pod{}
		if err := resources.ToTyped(pod, resource); err != nil {
			return nil, fmt.Errorf("%w - unable to convert to pod to typed object", err)
		}

		return &pod.Spec, nil
	case "Deployment":
		deployment := &appsv1.Deployment{}
		if err := resources.ToTyped(deployment, resource); err != nil {
			return nil, fmt.Errorf("%w - unable to convert deployment to typed object", err)
		}

		return &deployment.Spec.Template.Spec, nil
	case "StatefulSet":
		statefulSet := &appsv1.StatefulSet{}
		if err := resources.ToTyped(statefulSet, resource); err != nil {
			return nil, fmt.Errorf("%w - unable to convert stateful set to typed object", err)
		}

		return &statefulSet.Spec.Template.Spec, nil
	case "DaemonSet":
		daemonSet := &appsv1.DaemonSet{}
		if err := resources.ToTyped(daemonSet, resource); err != nil {
			return nil, fmt.Errorf("%w - unable to convert daemon set to typed object", err)
		}

		return &daemonSet.Spec.Template.Spec, nil
	case "CronJob":
		cronJob := &batchv1.CronJob{}
		if err := resources.ToTyped(cronJob, resource); err != nil {
			return nil, fmt.Errorf("%w - unable to convert cron job to typed object", err)
		}

		return &cronJob.Spec.JobTemplate.Spec.Template.Spec, nil
	case "Job":
		job := &batchv1.Job{}
		if err := resources.ToTyped(job, resource); err != nil {
			return nil, fmt.Errorf("%w - unable to convert job to typed object", err)
		}

		return &job.Spec.Template.Spec, nil
	default:
		return nil, fmt.Errorf("%w - [%s]", ErrValidatingKind, resource.GetObjectKind().GroupVersionKind().Kind)
	}
}

// GetSecurityContext returns the security context for a container.
//nolint:gocritic
// TODO: pass container as pointer.  this has implications when passing in a loop
//       as you need to avoid implicit memory aliasing in a loop to accomplish this.
func GetSecurityContext(container corev1.Container) corev1.SecurityContext {
	if container.SecurityContext == nil {
		return corev1.SecurityContext{}
	}

	return *container.SecurityContext
}

// GetContainerNames returns the container names for an array of containers.
func GetContainerNames(containers []corev1.Container) (names string) {
	for i := range containers {
		if names == "" {
			names = containers[i].Name

			continue
		}

		names = fmt.Sprintf("%s,%s", names, containers[i].Name)
	}

	return names
}

// HasRequiredCapability returns true if a required capability is found.
func HasRequiredCapability(capabilities []corev1.Capability, oneOf ...string) bool {
	for i := range capabilities {
		for j := range oneOf {
			if strings.EqualFold(string(capabilities[i]), oneOf[j]) {
				return true
			}
		}
	}

	return false
}

// EffectiveRunAsNonRoot determines if the container is effectively enforcing non-root containers.
func EffectiveRunAsNonRoot(podSec *corev1.PodSecurityContext, containerSec *corev1.SecurityContext) bool {
	if containerSec != nil && containerSec.RunAsNonRoot != nil {
		return *containerSec.RunAsNonRoot
	}

	if podSec != nil && podSec.RunAsNonRoot != nil {
		return *podSec.RunAsNonRoot
	}

	return false
}

// EffectiveRunAsUser determines the effective run as user id.
func EffectiveRunAsUser(podSec *corev1.PodSecurityContext, containerSec *corev1.SecurityContext) *int64 {
	if containerSec != nil && containerSec.RunAsUser != nil {
		return containerSec.RunAsUser
	}

	if podSec != nil {
		return podSec.RunAsUser
	}

	return nil
}

// ToString converts an object to a string which is useful while producing consistent logs.  This is safe to
// return via an admission review object, as sometimes certain characters can cause the response to the
// kube-apiserver to fail.
func ToString(object client.Object) string {
	return fmt.Sprintf(
		"%s/%s in namespace %s",
		object.GetObjectKind().GroupVersionKind().Kind,
		object.GetName(),
		object.GetNamespace(),
	)
}

// GetAnnotation gets an annotation from a resource in a manner that will not panic
// with a nil pointer dereference error.
func GetAnnotation(resource client.Object, annotationKey string) string {
	annotations := resource.GetAnnotations()
	if annotations == nil {
		return ""
	}

	return annotations[annotationKey]
}

// SkipViaAnnotations determines if a resource needs to be skipped due to the annotations
// that it possesses.
func SkipViaAnnotations(resource client.Object, overrideKey string) bool {
	return GetAnnotation(resource, overrideKey) != ""
}

// SkipViaOwnerReferences determines if a resource needs to be skipped due to the owner
// references that it possesses.
func SkipViaOwnerReferences(resource client.Object) bool {
	// if we are not working with a pod we cannot skip
	if resource.GetObjectKind().GroupVersionKind().Kind != "Pod" {
		return false
	}

	// if we do not have owner references we cannot skip
	if len(resource.GetOwnerReferences()) == 0 {
		return false
	}

	// if this is a pod and it is owned by one of the other controllers we are already validating, we
	// do not need to valiate this pod again
	for _, ownerRef := range resource.GetOwnerReferences() {
		for _, validOwner := range []string{
			"ReplicaSet",
			"Deployment",
			"DaemonSet",
			"StatefulSet",
			"CronJob",
			"Job",
		} {
			if ownerRef.Kind == validOwner {
				return true
			}
		}
	}

	return false
}
