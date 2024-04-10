/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package app

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"time"

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/apis/apiserver"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/authenticatorfactory"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/authorization/authorizerfactory"
	"k8s.io/apiserver/pkg/authorization/cel"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"
	genericoptions "k8s.io/apiserver/pkg/server/options"
	"k8s.io/apiserver/plugin/pkg/authorizer/webhook"
	webhookmetrics "k8s.io/apiserver/plugin/pkg/authorizer/webhook/metrics"
	clientset "k8s.io/client-go/kubernetes"
	authenticationclient "k8s.io/client-go/kubernetes/typed/authentication/v1"
	authorizationclient "k8s.io/client-go/kubernetes/typed/authorization/v1"
	"k8s.io/client-go/rest"
	kubeletconfig "k8s.io/kubernetes/pkg/kubelet/apis/config"
	"k8s.io/kubernetes/pkg/kubelet/server"
)

// BuildAuth creates an authenticator, an authorizer, and a matching authorizer attributes getter compatible with the kubelet's needs
// It returns AuthInterface, a run method to start internal controllers (like cert reloading) and error.
func BuildAuth(nodeName types.NodeName, client clientset.Interface, config kubeletconfig.KubeletConfiguration) (server.AuthInterface, func(<-chan struct{}), error) {
	// Get clients, if provided
	var (
		tokenClient authenticationclient.AuthenticationV1Interface
		sarClient   authorizationclient.AuthorizationV1Interface
	)
	if client != nil && !reflect.ValueOf(client).IsNil() {
		tokenClient = client.AuthenticationV1()
		sarClient = client.AuthorizationV1()
	}

	authenticator, runAuthenticatorCAReload, err := BuildAuthn(tokenClient, config.Authentication)
	if err != nil {
		return nil, nil, err
	}

	attributes := server.NewNodeAuthorizerAttributesGetter(nodeName)

	authorizer, err := BuildAuthz(sarClient, config.Authorization)
	if err != nil {
		return nil, nil, err
	}

	return server.NewKubeletAuth(authenticator, attributes, authorizer), runAuthenticatorCAReload, nil
}

// BuildAuthn creates an authenticator compatible with the kubelet's needs
func BuildAuthn(client authenticationclient.AuthenticationV1Interface, authn kubeletconfig.KubeletAuthentication) (authenticator.Request, func(<-chan struct{}), error) {
	var dynamicCAContentFromFile *dynamiccertificates.DynamicFileCAContent
	var err error
	if len(authn.X509.ClientCAFile) > 0 {
		dynamicCAContentFromFile, err = dynamiccertificates.NewDynamicCAContentFromFile("client-ca-bundle", authn.X509.ClientCAFile)
		if err != nil {
			return nil, nil, err
		}
	}

	authenticatorConfig := authenticatorfactory.DelegatingAuthenticatorConfig{
		Anonymous:                          authn.Anonymous.Enabled,
		CacheTTL:                           authn.Webhook.CacheTTL.Duration,
		ClientCertificateCAContentProvider: dynamicCAContentFromFile,
	}

	if authn.Webhook.Enabled {
		if client == nil {
			return nil, nil, errors.New("no client provided, cannot use webhook authentication")
		}
		authenticatorConfig.WebhookRetryBackoff = genericoptions.DefaultAuthWebhookRetryBackoff()
		authenticatorConfig.TokenAccessReviewClient = client
	}

	authenticator, _, err := authenticatorConfig.New()
	if err != nil {
		return nil, nil, err
	}

	return authenticator, func(stopCh <-chan struct{}) {
		// generate a context from stopCh. This is to avoid modifying files which are relying on this method
		// TODO: See if we can pass ctx to the current method
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			select {
			case <-stopCh:
				cancel() // stopCh closed, so cancel our context
			case <-ctx.Done():
			}
		}()
		if dynamicCAContentFromFile != nil {
			go dynamicCAContentFromFile.Run(ctx, 1)
		}
	}, err
}

// BuildAuthz creates an authorizer compatible with the kubelet's needs
func BuildAuthz(client authorizationclient.AuthorizationV1Interface, authz kubeletconfig.KubeletAuthorization) (authorizer.Authorizer, error) {
	switch authz.Mode {
	case kubeletconfig.KubeletAuthorizationModeAlwaysAllow:
		return authorizerfactory.NewAlwaysAllowAuthorizer(), nil

	case kubeletconfig.KubeletAuthorizationModeWebhook:
		if client == nil {
			return nil, errors.New("no client provided, cannot use webhook authorization")
		}
		authorizerConfig := authorizerfactory.DelegatingAuthorizerConfig{
			SubjectAccessReviewClient: client,
			AllowCacheTTL:             authz.Webhook.CacheAuthorizedTTL.Duration,
			DenyCacheTTL:              authz.Webhook.CacheUnauthorizedTTL.Duration,
			WebhookRetryBackoff:       genericoptions.DefaultAuthWebhookRetryBackoff(),
		}
		return authorizerConfig.New()

	case kubeletconfig.KubeletAuthorizationModeLocal:
		return NewlocalAuthorizer(), nil

	case "":
		return nil, fmt.Errorf("no authorization mode specified")

	default:
		return nil, fmt.Errorf("unknown authorization mode %s", authz.Mode)

	}
}

func NewlocalAuthorizer() *localAuthorizer {
	return new(localAuthorizer)
}

// localAuthorizer is an implementation of authorizer.Attributes
// which check local webhook to an authorization request.
// It is useful in confidential worker node where API server is not trusted.
type localAuthorizer struct{}

type kubeletWebhookMetrics struct {
	// kube-apiserver doesn't report request metrics
	webhookmetrics.NoopRequestMetrics
	// kube-apiserver does report webhook metrics
	webhookmetrics.WebhookMetrics
	// kube-apiserver does report matchCondition metrics
	cel.MatcherMetrics
}

func (localAuthorizer) Authorize(ctx context.Context, a authorizer.Attributes) (authorized authorizer.Decision, reason string, err error) {
	// Create a REST client instance to Open Policy Agent server.
	clientConfig := rest.Config{
		Host:    "http://localhost:8181",
		APIPath: "v1/data",
	}

	var decisionOnError authorizer.Decision
	// Create a Backoff instance with example values
	backoffConfig := wait.Backoff{
		Duration: 100 * time.Millisecond, // Initial delay of 100 milliseconds
		Factor:   2.0,                    // Double the delay on each retry
		Jitter:   0.2,                    // Add up to 20% random jitter
		Steps:    5,                      // Allow up to 5 retries
		Cap:      5 * time.Second,        // Maximum delay of 5 seconds
	}

	var emptyMatchConditions []apiserver.WebhookMatchCondition

	webhookAuthorizer, err := webhook.New(&clientConfig,
		"v1beta1",
		5*time.Minute,
		5*time.Minute,
		backoffConfig,
		decisionOnError,
		emptyMatchConditions,
		"Local OPA webhook",
		kubeletWebhookMetrics{WebhookMetrics: webhookmetrics.NewWebhookMetrics(), MatcherMetrics: cel.NewMatcherMetrics()},
	)
	if err != nil {
		return 0, "Failed to create local webhook authorizer: %v", err
	}
	return webhookAuthorizer.Authorize(ctx, a)
}

func NewAlwaysAllowAuthorizer() *localAuthorizer {
	return new(localAuthorizer)
}
