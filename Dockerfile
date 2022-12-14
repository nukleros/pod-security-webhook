# Build the manager binary
FROM golang:1.18 as builder

WORKDIR /workspace
# Copy the Go Modules manifests
# NOTE: when copying in new files, be sure to update the .goreleaser.yml file as those
#       files also need to be explicitly added.
COPY go.mod go.mod
COPY go.sum go.sum
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

# Copy the go source
# NOTE: when copying in new files, be sure to update the .goreleaser.yml file as those
#       files also need to be explicitly added.
COPY main.go main.go
COPY webhook/ webhook/
COPY resources/ resources/
COPY validate/ validate/

# Build
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -o webhook main.go

# Use distroless as minimal base image to package the manager binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details
FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /workspace/webhook .
USER 65532:65532

ENTRYPOINT ["/webhook"]
