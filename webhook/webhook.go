// Copyright 2022 Nukleros
// SPDX-License-Identifier: MIT

package webhook

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"github.com/apsdehal/go-logger"
	"github.com/gorilla/mux"

	admissionv1 "k8s.io/api/admission/v1"
	v1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	"sigs.k8s.io/controller-runtime/pkg/client"

	webhookresources "github.com/nukleros/pod-security-webhook/resources"
	"github.com/nukleros/pod-security-webhook/validate"
)

const (
	tlsCertEnv = "TLS_CERT"
	tlsKeyEnv  = "TLS_KEY"
	portEnv    = "WEBHOOK_PORT"
	debugEnv   = "DEBUG"

	defaultTlsCertEnv = "/ssl_certs/tls.crt"
	defaultTlsKeyEnv  = "/ssl_certs/tls.key"
	defaultPort       = 8443
)

type Webhook struct {
	Certificate *tls.Certificate
	Client      kubernetes.Interface
	Log         *logger.Logger
	Router      *mux.Router
	Port        int
}

type WebhookOperationStep func(http.ResponseWriter, *http.Request, *WebhookOperation) (error, int)

type WebhookOperation struct {
	Log         *logger.Logger
	Resource    client.Object
	PodSpec     *corev1.PodSpec
	Validations []*validate.Validation
	Review      *admissionv1.AdmissionReview

	// functions
	OperationStep []WebhookOperationStep
	RegisterFunc  func()

	// admission for this operation
	Patches        []map[string]string
	Permitted      bool
	ResponseError  error
	ResponseReason metav1.StatusReason
	StatusCode     int
}

func NewWebhook() (*Webhook, error) {
	// get the kubernetes client
	kubernetesClient, err := getClient()
	if err != nil {
		return nil, fmt.Errorf("%w - error creating client object for webhook", err)
	}

	// get the logger
	log, err := logger.New("webhook", 0, os.Stdout)
	if err != nil {
		return nil, fmt.Errorf("%w - error creating logger object for webhook", err)
	}

	if os.Getenv(debugEnv) == "true" {
		log.SetLogLevel(logger.DebugLevel)
	}

	// get the certificates
	cert, key := os.Getenv(tlsCertEnv), os.Getenv(tlsKeyEnv)
	if cert == "" {
		cert = defaultTlsCertEnv
	}

	if key == "" {
		key = defaultTlsKeyEnv
	}

	tlsPair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		return nil, fmt.Errorf("%w - error loading x509 key pair from cert: [%s] and key: [%s]", err, cert, key)
	}

	// create the webhook
	webhook := &Webhook{
		Certificate: &tlsPair,
		Client:      kubernetesClient,
		Log:         log,
	}

	// get the port
	port := os.Getenv(portEnv)
	if port == "" {
		webhook.Port = defaultPort
	} else {
		portInt, err := strconv.Atoi(port)
		if err != nil {
			return nil, fmt.Errorf("%w - error converting port environment variable to integer: [%s]", err, port)
		}

		webhook.Port = portInt
	}

	// set the handler functions and return
	router := mux.NewRouter()
	router.HandleFunc("/validate", webhook.validate)
	router.HandleFunc("/healthz", webhook.healthCheck)

	webhook.Router = router

	return webhook, nil
}

// getClient returns a valid kubernetes client used for interacting with the cluster.
func getClient() (kubernetes.Interface, error) {
	var config *rest.Config

	var err error

	// read kubeconfig from environment
	kubeConfig := os.Getenv("KUBECONFIG")
	if kubeConfig != "" {
		if config, err = clientcmd.BuildConfigFromFlags("", kubeConfig); err != nil {
			return nil, fmt.Errorf("%w - error loading kubeconfig from environment variable KUBECONFIG: [%s]", err, kubeConfig)
		}

		return kubernetes.NewForConfig(config)
	}

	// read kubeconfig from home directory
	if home := homedir.HomeDir(); home != "" {
		kubeConfig = filepath.Join(home, ".kube", "config")
		if _, err := os.Stat(kubeConfig); err == nil {
			if config, err = clientcmd.BuildConfigFromFlags("", kubeConfig); err == nil {
				return nil, fmt.Errorf("%w - error loading kubeconfig from home path: [%s]", err, kubeConfig)
			}

			return kubernetes.NewForConfig(config)
		}
	}

	// finally try to get in-cluster config via service account
	if config, err = rest.InClusterConfig(); err != nil {
		return nil, fmt.Errorf("%w - error loading in-cluster kubernetes client config", err)
	}

	return kubernetes.NewForConfig(config)
}

// writeErrorMessage writes error message to stderr and the http stream.
func (webhook *Webhook) writeErrorMessage(w http.ResponseWriter, msg error, code int) {
	w.Header().Set("Content-Type", "application/json")
	webhook.Log.Error(msg.Error())
	http.Error(w, msg.Error(), code)
}

// performSetup performs prevalidation prior to actually running the tests to ensure that we
// have a clean input.
func (webhook *Webhook) performSetup(w http.ResponseWriter, r *http.Request, operation *WebhookOperation) (error, int) {
	input := admissionv1.AdmissionReview{}

	// decode the request input into a typed object
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		return fmt.Errorf("%w - unable to decode the POST request", err), http.StatusBadRequest
	}

	// check for various nil or empty values
	if input.Request == nil || input.Request.RequestKind == nil {
		return fmt.Errorf("invalid request - request object is nil"), http.StatusBadRequest
	}

	// ensure the object in the request is not empty
	if len(input.Request.Object.Raw) < 0 {
		return fmt.Errorf("invalid request - empty object in request"), http.StatusBadRequest
	}

	// set fields that we need on the webhook object
	object := unstructured.Unstructured{}
	if err := json.Unmarshal(input.Request.Object.Raw, &object); err != nil {
		return fmt.Errorf(
			"%w - unable to unmarshal request object to unstructured object",
			err,
		), http.StatusInternalServerError
	}

	podSpec, err := webhookresources.GetPodSpec(&object)
	if err != nil {
		return fmt.Errorf("%w - error retrieving pod specification from object", err), http.StatusInternalServerError
	}

	operation.Review = &input
	operation.PodSpec = podSpec
	operation.Resource = &object

	// run the function to register the operation
	operation.RegisterFunc()

	return nil, -1
}

// run runs through a webhook operation.  It returns any errors and an integer that represents
// a status code.
func (operation *WebhookOperation) run(webhook *Webhook, w http.ResponseWriter, r *http.Request) {
	for _, handlerFunc := range operation.OperationStep {
		operation.ResponseError, operation.StatusCode = handlerFunc(w, r, operation)

		if operation.ResponseError != nil {
			if operation.StatusCode != -1 {
				operation.StatusCode = http.StatusForbidden
			}

			webhook.Log.Error(operation.ResponseError.Error())

			// respond with an internal error message and register a response error
			// if that fails
			responseErr := webhook.respond(w, operation)
			if responseErr != nil {
				webhook.writeErrorMessage(
					w, fmt.Errorf("%w - %s - error sending response",
						operation.ResponseError,
						responseErr),
					http.StatusInternalServerError,
				)
			}

			return
		}
	}

	// if none of our operations failed, pass an allow=true response with an http.StatusOK status
	operation.StatusCode = http.StatusOK

	operation.Permitted = true
	if err := webhook.respond(w, operation); err != nil {
		webhook.writeErrorMessage(w, fmt.Errorf("%w - error sending response", err), http.StatusInternalServerError)
	}
}

// respond send the response back to the main processing loop.
func (webhook *Webhook) respond(w http.ResponseWriter, operation *WebhookOperation) error {
	// set the response fields
	operation.Review.Response = &admissionv1.AdmissionResponse{
		UID:     operation.Review.Request.UID,
		Allowed: operation.Permitted,
		Result:  &metav1.Status{Code: int32(operation.StatusCode)},
	}

	// set the response error
	if operation.ResponseError != nil {
		operation.Review.Response.Result.Message = operation.ResponseError.Error()
	}

	// set the response reason
	if !operation.Permitted {
		operation.Review.Response.Result.Reason = metav1.StatusReasonForbidden
	}

	// set the patches if we are mutating
	if len(operation.Patches) > 0 {
		patchType := v1.PatchTypeJSONPatch
		operation.Review.Response.PatchType = &patchType

		patchData, err := json.Marshal(operation.Patches)
		if err != nil {
			return fmt.Errorf("%w - unable to marshal patches", err)
		}

		operation.Review.Response.Patch = patchData
	}

	w.Header().Set("Content-Type", "application/json")

	response, err := json.Marshal(operation.Review)
	if err != nil {
		return fmt.Errorf("%w - unable to marshal the json response", err)
	}

	if _, err := w.Write(response); err != nil {
		return fmt.Errorf("%w - unable to send HTTP response", err)
	}

	webhook.Log.Debug("sending response")
	webhook.Log.Debugf("%s", response)

	return nil
}
