# pod-security-webhook

This project aims to simplify the admission validation process for admitting applications
into a Kubernetes cluster.  It was first implemented as an MVP to meet the standards
for the [EKS CIS Benchmark](https://aws.amazon.com/blogs/containers/introducing-cis-amazon-eks-benchmark/).  However,
it was written in a flexible enough manner to maintain relatively as new security policies
are discovered.

This is intended to provide an alternative to other solutions for those who may find
comfort in a pure, direct webhook implementation, rather than any sort of abstraction.

## Why Not Pod Security Policies?

The reason to choose a project such as this over Pod Security Policies is simply for
future proofing.  It is well documented that the existing Pod Security Policy standard
is deprecated in Kubernetes 1.21 and set to be completely remove by Kubernetes 1.25.
See https://kubernetes.io/blog/2021/04/06/podsecuritypolicy-deprecation-past-present-and-future/
for more details.  By using a project like this, you can ensure that, so long as the
concept of a ValidatingWebhookConfiguration exists in Kuberentes, your security
policies will continue to work.

## Why Not Pod Security Standards/Pod Security Admission?

[Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/) and
[Pod Security Admission](https://kubernetes.io/docs/concepts/security/pod-security-admission/) are the
built-in replacement for Pod Security Policies.  To be honest, we have not spent much time in
this space, however, the linked documentation above implies that these standards are applied
at the namespace level.  While that is great in theory, in practice there sometimes are a more
granular set of standards that need to happen at a lower-level.

## Why Not Gatekeeper?

[Gatekeeper](https://github.com/open-policy-agent/gatekeeper) is a popular project designed to allow
the flexibility of implementing custom policies in a DSL called OPA.  Our small experience s
with it led to many frustrations with attempting to understand a language that was
lightly documented and not very well understood.  And some of the things we were attempting to
do were close enough to actual programming that you may as well just be using your
own programming language.

Gatekeeper is a great project if you do not want to maintain your own independent webhhok, image,
certificate, etc., but we feel the language itself presents enough challenges to give
some pause to the idea of dynamic policy creation.

# Deploying the Webhook

There are 2 built-in approaches for deploying the webhook.  First approach is to provide your own
certificate for the webhook, which should follow the cert-manager certificate specification
that is defined [here](manifests/certificate.yaml).  This assumes that a secret with the certificate
data exists at `nukleros-admission-system/pod-security-webhook-cert`:

```
# create the certificate secret
kubectl -n nukleros-admission-system create secret tls pod-security-webhook-cert \
    --cert=./cert.pem \
    --key=./key.pem

# deploy the webhook
make deploy
```

The second approach implies the use of cert-manager to deploy, with a `ClusterIssuer`
resource named `root-ca`:

```
# deploy the webhook
make deploy-cert-manager
```

# Using the Webhook

## Integration with StackRox kube-linter

This project also integrates with [kube-linter](https://github.com/stackrox/kube-linter) to allow
for deduplication of CI pipelines versus cluster-side policy.  This implements a system of
checks (CI pipeline) and balances (runtime admission) without having to redefine a set of
annotations for both.

## Disabling Admission Checks Globally

Obviously there comes a point where a certain use case may call for these integrations to
be disabled for **all** pods that are admitted to the cluster.  In such an instance, there
is a ConfigMap that may be modified to disable the undesired integration:

```
kubectl -n nukleros-admission-system edit configmap pod-security-webhook

...
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: pod-security-webhook
  namespace: nukleros-admission-system
data:
  DEBUG: "false"
  VALIDATE_VERIFY_DROP_CONTAINER_CAPABILITIES: "true"
  VALIDATE_VERIFY_ADD_CONTAINER_CAPABILITIES: "true"
  VALIDATE_HOST_PID: "false"  <<< disable host_pid checks
  VALIDATE_HOST_IPC: "true"
  VALIDATE_HOST_NETWORK: "false"  <<< disable host_network checks
  VALIDATE_RUN_AS_NON_ROOT: "true"
  VALIDATE_PRIVILEGED_CONTAINER: "true"
  VALIDATE_PRIVILEGE_ESCALATION_CONTAINER: "true"
  TRUSTED_IMAGE_REGISTRY: "ghcr.io"

```

## Disabling Admission Checks Per Resource

For each resource, you can disable the admssion check by simply implementing kube-linter
annotations on the resource in question.  See [Available Admission Checks](#available-admission-checks)
for more details.

## Available Admission Checks

The following is the current set of admission checks.  They can be disabled by
applying kube-linter annotations to the resource that needs to specifically disable them by
applying `ignore-check.kube-linter.io/<NAME>` using the appropraite name below.  Documentation
on these can be found at https://docs.kubelinter.io/#/generated/checks:

* host-ipc                           |
* host-pid                           |
* host-network
* privileged-container
* privilege-escalation-container
* run-as-non-root
* verify-add-container-capabilities
* verify-drop-container-capabilities

The following are additional checks implemented outside of kube-linter.  For now, they
use the same standard `ignore-check.kube-linter.io/<NAME>`:

* trusted-image-registries - ensure a deployment-like resource belongs to one of a comma-separated-list
  of image registries.

## Contributing

We would love to add to this and make it more usable for others!  The process to add a new validation to this
we feel is pretty simple.  You can do the following:

1. Write your validation in the [validate](validate/) folder.  Here is an example of what a validation
   looks like and what one looks like:


```go
// Validation object
type Validation struct {
	Name     string
	Resource client.Object
	PodSpec  *corev1.PodSpec
	Run      ValidationLogic
	Skip     bool
}

// This is a REAL validation
// ValidateHostPID validates whether a pod spec has the hostPID value set.
func ValidateHostPID(validation *Validation) (bool, error) {
	if validation.PodSpec.HostPID {
		return validation.Failed(ErrPodHostPID)
	}

	return true, nil
}

// This is a sample validation adding something new.
// NOTE: this is not a suggestion, just showing what may be validated.
const (
  // this allows us to apply the ignore-check.kube-linter.io/my-new-thing annotation
  // in order to allow us to skip it for individual resources.  it also allows us to
  // use the VALIDATE_MY_NEW_THING = "false" environment variable to skip the
  // validation globally.
  SkipMyNewThingValidation = "my-new-thing"
)

func ValidateMyNewThing(validation *Validation) (bool, error) {
	if validation.Replicas < 3 {
		return validation.Failed(fmt.Errorf("need a minimum of 3 replicas"))
	}

	return true, nil
}
```

2. Add your validation to the registry at [webhook/validate.go](webhook/validate.go):

```go
// registerValidations registers all validations that are know to this webhook.
func (operation *WebhookOperation) registerValidations() {
  operation.registerValidation(validate.NewValidation(validate.SkipMyNewThingValidation, validate.ValidateMyNewThing))
}
```

3. Write your unit test to ensure that your validation both is successful and unsuccessful.  Several
   examples are listed with the `*_test.go` in the [validate](validate/) folder.

# Summary

That's it!  We hope you find this is a usefull alternative for existing tooling already.  Cheers!
