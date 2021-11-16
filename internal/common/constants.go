/*
Copyright IBM Corporation 2021

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

package common

import (
	"net/http"
	"regexp"

	"github.com/Nerzal/gocloak/v8"
	"github.com/konveyor/move2kube-api/internal/types"
)

const (
	// APP_NAME stores the application name
	APP_NAME = "move2kube"
	// APP_NAME_SHORT stores the application shortname
	APP_NAME_SHORT = "m2k"
	// SESSIONS_DIR is the name of the directory where the sessions are stored
	SESSIONS_DIR = "sessions"
	// LOGIN_PATH is the URL endpoint to start the login flow
	LOGIN_PATH = "/auth/login"
	// LOGIN_CALLBACK_PATH is the URL endpoint to finish the login flow
	LOGIN_CALLBACK_PATH = LOGIN_PATH + "/callback"
	// CONTENT_TYPE_JSON is the MIME type for json body
	CONTENT_TYPE_JSON = "application/json"
	// CONTENT_TYPE_FORM_URL_ENCODED is the MIME type for URL encoded request bodies
	CONTENT_TYPE_FORM_URL_ENCODED = "application/x-www-form-urlencoded"
	// CONTENT_TYPE_BINARY is the MIME type for binary body
	CONTENT_TYPE_BINARY = "application/octet-stream"
	// CONTENT_TYPE_CLOUD_EVENT is the MIME type for CloudEvents spec json body
	CONTENT_TYPE_CLOUD_EVENT = "application/cloudevents+json"
	// AUTHENTICATE_HEADER_MSG is the message returned in the authentication header
	AUTHENTICATE_HEADER_MSG = `Bearer realm="Access to the Move2Kube API."`
	// OIDC_DISCOVERY_ENDPOINT_PATH is the OIDC discovery endpoint
	OIDC_DISCOVERY_ENDPOINT_PATH = "/realms/%s/.well-known/openid-configuration"
	// UMA_CONFIGURATION_ENDPOINT_PATH is the well known UMA endpoint
	UMA_CONFIGURATION_ENDPOINT_PATH = "/realms/%s/.well-known/uma2-configuration"
	// IDP_ID_ROUTE_VAR is the route variable for the identity provider id
	IDP_ID_ROUTE_VAR = "idp-id"
	// DELIM is the route variable for separating the identity provider id and the user id
	DELIM = "# $ #"
)

var (
	// Config contains the entire configuration for the API server
	Config types.ConfigT
	// AuthServerClient is the client used to interface with the Authorization server
	AuthServerClient gocloak.GoCloak
	// ID_REGEXP is the regexp used to check if a Id is valid
	ID_REGEXP = regexp.MustCompile("^[a-zA-Z0-9-_]+$")
	// INVALID_NAME_CHARS_REGEXP is the regexp used to replace invalid name characters with hyphen
	INVALID_NAME_CHARS_REGEXP = regexp.MustCompile("[^a-z0-9-]")
	// AUTHZ_HEADER is the authorization header
	AUTHZ_HEADER = http.CanonicalHeaderKey("Authorization")
	// AUTHENTICATE_HEADER is the authentication header
	AUTHENTICATE_HEADER = http.CanonicalHeaderKey("WWW-Authenticate")
	// CONTENT_TYPE_HEADER is the content type header
	CONTENT_TYPE_HEADER = http.CanonicalHeaderKey("Content-Type")
	// KNOWN_API_VERSIONS is the list of known Move2Kube apiVersions
	KNOWN_API_VERSIONS = []string{"move2kube.konveyor.io/v1alpha1"}
)
