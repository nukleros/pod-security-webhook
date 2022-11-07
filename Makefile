#
# build image
#
IMG ?= ghcr.io/nukleros/pod-security-webhook
VERSION ?= latest
docker-build:
	@docker build -t $(IMG):$(VERSION) .

docker-push:
	@docker push $(IMG):$(VERSION)

#
# deploy
#

# deploy assumes the existence of your webhook certificate at pod-security-webhook in whichever
# namespace you are deploying into.
deploy:
	@kubectl apply -f manifests/namespace.yaml
	@kubectl apply -f manifests/pod-security-webhook.yaml

# deploy-cert-manager assumes the existence of cert-manager with a cluster issuer names root-ca.
deploy-cert-manager:
	@kubectl apply -f manifests/namespace.yaml
	@kubectl apply -f manifests/certificate.yaml
	@kubectl apply -f manifests/pod-security-webhook.yaml

#
# tests
#
GOLANGCI_LINT_VERSION ?= v1.50.1
install-linter:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

lint:
	golangci-lint run

test:
	@go test -cover -coverprofile=./coverage.out ./...

test-commit:
	scripts/commit-check-latest.sh

lint-k8s:
	@kube-linter lint manifests/ --config .kube-lint.yml

lint-yaml:
	@yamllint ./
