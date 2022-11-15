/*
Copyright IBM Corporation 2020

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

package types

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Nerzal/gocloak/v10"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

// ConfigT hold the entire configuration for starting the server
type ConfigT struct {
	VersionLong                  bool     `mapstructure:"version-long"`
	SecureCookies                bool     `mapstructure:"secure-cookies"`
	AuthEnabled                  bool     `mapstructure:"auth-enabled"`
	EnableLocalExecution         bool     `mapstructure:"enable-local-execution"`
	CleanUpAfterTransform        bool     `mapstructure:"clean-up-after-transform"`
	CloudEventsEnabled           bool     `mapstructure:"cloud-events-enabled"`
	Port                         int      `mapstructure:"port"`
	CookieMaxAge                 int      `mapstructure:"cookie-max-age"`
	MaxUploadSize                int64    `mapstructure:"max-upload-size"`
	PlanTimeoutSeconds           int64    `mapstructure:"plan-timeout-seconds"`
	TransformTimeoutSeconds      int64    `mapstructure:"transform-timeout-seconds"`
	LogLevel                     string   `mapstructure:"log-level"`
	DataDir                      string   `mapstructure:"data-dir"`
	StaticFilesDir               string   `mapstructure:"static-files-dir"`
	SessionSecret                string   `mapstructure:"session-secret"`
	CurrentHost                  string   `mapstructure:"current-host"`
	AuthServer                   string   `mapstructure:"auth-server"`
	AuthServerBasePath           string   `mapstructure:"auth-server-base-path"`
	AuthServerLoginPath          string   `mapstructure:"auth-server-login-path"`
	AuthServerTimeout            int      `mapstructure:"auth-server-timeout"`
	AuthServerRealm              string   `mapstructure:"auth-server-realm"`
	OIDCDiscoveryEndpointPath    string   `mapstructure:"oidc-discovery-endpoint-path"`
	UMAConfigurationEndpointPath string   `mapstructure:"uma-configuration-endpoint-path"`
	M2kClientClientId            string   `mapstructure:"m2k-client-client-id"`
	M2kClientClientSecret        string   `mapstructure:"m2k-client-client-secret"`
	M2kClientIdNotClientId       string   `mapstructure:"m2k-client-id-not-client-id"`
	M2kServerClientId            string   `mapstructure:"m2k-server-client-id"`
	M2kServerClientSecret        string   `mapstructure:"m2k-server-client-secret"`
	DefaultResourceId            string   `mapstructure:"default-resource-id"`
	Host                         string   `mapstructure:"host"`
	CertPath                     string   `mapstructure:"https-cert"`
	KeyPath                      string   `mapstructure:"https-key"`
	CloudEventsEndpoint          string   `mapstructure:"cloud-events-endpoint"`
	CloudEventsAccessToken       string   `mapstructure:"cloud-events-access-token"`
	CloudEventsSpecVersion       string   `mapstructure:"cloud-events-spec-version"`
	CloudEventsType              string   `mapstructure:"cloud-events-type"`
	CloudEventsSubject           string   `mapstructure:"cloud-events-subject"`
	OIDCInfo                     OIDCInfo `mapstructure:"-"`
	UMAInfo                      UMAInfo  `mapstructure:"-"`
}

// M2kClientBasicAuth returns the encoded basic auth using client id and secret
func (c ConfigT) M2kClientBasicAuth() string {
	return base64.StdEncoding.EncodeToString([]byte(c.M2kClientClientId + ":" + c.M2kClientClientSecret))
}

// M2kServerBasicAuth returns the encoded basic auth using server id and secret
func (c ConfigT) M2kServerBasicAuth() string {
	return base64.StdEncoding.EncodeToString([]byte(c.M2kServerClientId + ":" + c.M2kServerClientSecret))
}

func (c ConfigT) String() string {
	configYamlBytes, err := yaml.Marshal(c)
	if err != nil {
		logrus.Errorf("failed to marshal the config struct to yaml. Error: %q", err)
		return ""
	}
	return string(configYamlBytes)
}

// QAServerMetadata stores serializable runtime REST access information
type QAServerMetadata struct {
	Host  string `json:"host" yaml:"host"`
	Port  int    `json:"port" yaml:"port"`
	Debug bool   `json:"debug" yaml:"debug"`
}

// OIDCInfo contains the info returned by the OIDC discovery endpoint
type OIDCInfo struct {
	Issuer                                                    string            `json:"issuer"`
	AuthorizationEndpoint                                     string            `json:"authorization_endpoint"`
	TokenEndpoint                                             string            `json:"token_endpoint"`
	IntrospectionEndpoint                                     string            `json:"introspection_endpoint"`
	UserinfoEndpoint                                          string            `json:"userinfo_endpoint"`
	EndSessionEndpoint                                        string            `json:"end_session_endpoint"`
	JwksURI                                                   string            `json:"jwks_uri"`
	CheckSessionIframe                                        string            `json:"check_session_iframe"`
	GrantTypesSupported                                       []string          `json:"grant_types_supported,omitempty"`
	ResponseTypesSupported                                    []string          `json:"response_types_supported,omitempty"`
	SubjectTypesSupported                                     []string          `json:"subject_types_supported,omitempty"`
	IdTokenSigningAlgValuesSupported                          []string          `json:"id_token_signing_alg_values_supported,omitempty"`
	IdTokenEncryptionAlgValuesSupported                       []string          `json:"id_token_encryption_alg_values_supported,omitempty"`
	IdTokenEncryptionEncValuesSupported                       []string          `json:"id_token_encryption_enc_values_supported,omitempty"`
	UserinfoSigningAlgValuesSupported                         []string          `json:"userinfo_signing_alg_values_supported,omitempty"`
	RequestObjectSigningAlgValuesSupported                    []string          `json:"request_object_signing_alg_values_supported,omitempty"`
	RequestObjectEncryptionAlgValuesSupported                 []string          `json:"request_object_encryption_alg_values_supported,omitempty"`
	RequestObjectEncryptionEncValuesSupported                 []string          `json:"request_object_encryption_enc_values_supported,omitempty"`
	ResponseModesSupported                                    []string          `json:"response_modes_supported,omitempty"`
	RegistrationEndpoint                                      string            `json:"registration_endpoint"`
	TokenEndpointAuthMethodsSupported                         []string          `json:"token_endpoint_auth_methods_supported,omitempty"`
	TokenEndpointAuthSigningAlgValuesSupported                []string          `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`
	IntrospectionEndpointAuthMethodsSupported                 []string          `json:"introspection_endpoint_auth_methods_supported,omitempty"`
	IntrospectionEndpointAuthSigningAlgValuesSupported        []string          `json:"introspection_endpoint_auth_signing_alg_values_supported,omitempty"`
	AuthorizationSigningAlgValuesSupported                    []string          `json:"authorization_signing_alg_values_supported,omitempty"`
	AuthorizationEncryptionAlgValuesSupported                 []string          `json:"authorization_encryption_alg_values_supported,omitempty"`
	AuthorizationEncryptionEncValuesSupported                 []string          `json:"authorization_encryption_enc_values_supported,omitempty"`
	ClaimsSupported                                           []string          `json:"claims_supported,omitempty"`
	ClaimTypesSupported                                       []string          `json:"claim_types_supported,omitempty"`
	ClaimsParameterSupported                                  bool              `json:"claims_parameter_supported"`
	ScopesSupported                                           []string          `json:"scopes_supported,omitempty"`
	RequestParameterSupported                                 bool              `json:"request_parameter_supported"`
	RequestUriParameterSupported                              bool              `json:"request_uri_parameter_supported"`
	RequireRequestUriRegistration                             bool              `json:"require_request_uri_registration"`
	CodeChallengeMethodsSupported                             []string          `json:"code_challenge_methods_supported,omitempty"`
	TlsClientCertificateBoundAccessTokens                     bool              `json:"tls_client_certificate_bound_access_tokens"`
	RevocationEndpoint                                        string            `json:"revocation_endpoint"`
	RevocationEndpointAuthMethodsSupported                    []string          `json:"revocation_endpoint_auth_methods_supported,omitempty"`
	RevocationEndpointAuthSigningAlgValuesSupported           []string          `json:"revocation_endpoint_auth_signing_alg_values_supported,omitempty"`
	BackchannelLogoutSupported                                bool              `json:"backchannel_logout_supported"`
	BackchannelLogoutSessionSupported                         bool              `json:"backchannel_logout_session_supported"`
	DeviceAuthorizationEndpoint                               string            `json:"device_authorization_endpoint"`
	BackchannelTokenDeliveryModesSupported                    []string          `json:"backchannel_token_delivery_modes_supported,omitempty"`
	BackchannelAuthenticationEndpoint                         string            `json:"backchannel_authentication_endpoint"`
	BackchannelAuthenticationRequestSigningAlgValuesSupported []string          `json:"backchannel_authentication_request_signing_alg_values_supported,omitempty"`
	RequirePushedAuthorizationRequests                        bool              `json:"require_pushed_authorization_requests"`
	PushedAuthorizationRequestEndpoint                        string            `json:"pushed_authorization_request_endpoint"`
	MtlsEndpointAliases                                       map[string]string `json:"mtls_endpoint_aliases"`
}

// UMAInfo contains the info returned by the UMA well-known endpoint
type UMAInfo struct {
	Issuer                                     string   `json:"issuer"`
	AuthorizationEndpoint                      string   `json:"authorization_endpoint"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	IntrospectionEndpoint                      string   `json:"introspection_endpoint"`
	EndSessionEndpoint                         string   `json:"end_session_endpoint"`
	JwksURI                                    string   `json:"jwks_uri"`
	GrantTypesSupported                        []string `json:"grant_types_supported,omitempty"`
	ResponseTypesSupported                     []string `json:"response_types_supported,omitempty"`
	ResponseModesSupported                     []string `json:"response_modes_supported,omitempty"`
	RegistrationEndpoint                       string   `json:"registration_endpoint"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`
	ScopesSupported                            []string `json:"scopes_supported,omitempty"`
	ResourceRegistrationEndpoint               string   `json:"resource_registration_endpoint"`
	PermissionEndpoint                         string   `json:"permission_endpoint"`
	PolicyEndpoint                             string   `json:"policy_endpoint"`
}

// Tokens contains all the tokens returned during login
type Tokens struct {
	AccessToken  string `json:"access_token"`
	IdToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
}

// PermTicket contains the ticket used in the UMA grant flow
type PermTicket struct {
	Ticket string `json:"ticket"`
}

// PermRequest contains the permission request used in the UMA grant flow
type PermRequest struct {
	ResourceId     string   `json:"resource_id"`
	ResourceScopes []string `json:"resource_scopes"`
}

// Role contains all the information about a RBAC role
type Role struct {
	Metadata
	Rules []RoleRule
}

// RoleRule contains the list of resources and the verbs allowed on those resources
type RoleRule struct {
	Resources []string
	Verbs     []string
}

// GetRulesAsAttrs flattens and returns the rules of the role as a map suitable for creating an authz server role
func (r Role) GetRulesAsAttrs() map[string][]string {
	attrs := map[string][]string{}
	for _, rule := range r.Rules {
		for _, res := range rule.Resources {
			attrs[res] = rule.Verbs
		}
	}
	return attrs
}

// ToAuthServerRole converts the role to an authz server role
func (r Role) ToAuthServerRole() (gocloak.Role, error) {
	// since keycloak doesn't allow us to choose the role id,
	// we are storing the role id they give us in the name field of keycloak role (the role name field is unique in keycloak)
	// and we store both name and description they give us in the description field of keycloak role as json
	roleNameDescBytes, err := json.Marshal(map[string]string{"name": r.Name, "description": r.Description, "timestamp": r.Timestamp})
	if err != nil {
		return gocloak.Role{}, fmt.Errorf("failed to marshal the role to an auth server role. Error: %q", err)
	}
	roleNameDesc := string(roleNameDescBytes)
	attrs := r.GetRulesAsAttrs()
	return gocloak.Role{ID: &r.Id, Name: &r.Id, Description: &roleNameDesc, Attributes: &attrs}, nil
}

// FromAuthServerRole converts an authz server role to a role
func FromAuthServerRole(r gocloak.Role) Role {
	// since keycloak doesn't allow us to choose the role id,
	// we are storing the role id they give us in the name field of keycloak role (the role name field is unique in keycloak)
	// and we store both name and description they give us in the description field of keycloak role as json
	name := ""
	description := ""
	timestamp := ""
	if r.Description != nil {
		roleMap := map[string]string{}
		if err := json.Unmarshal([]byte(*r.Description), &roleMap); err == nil {
			name = roleMap["name"]
			description = roleMap["description"]
			timestamp = roleMap["timestamp"]
		}
	}
	rules := []RoleRule{}
	if r.Attributes != nil {
		for res, verbs := range *r.Attributes {
			rules = append(rules, RoleRule{Resources: []string{res}, Verbs: verbs})
		}
	}
	return Role{Metadata: Metadata{Id: *r.Name, Name: name, Description: description, Timestamp: timestamp}, Rules: rules}
}

// UserInfo holds all the identifying information about the user
type UserInfo gocloak.UserInfo

// Workspace holds information about a workspace
type Workspace struct {
	Metadata
	ProjectIds []string                `json:"project_ids,omitempty"`
	Inputs     map[string]ProjectInput `json:"inputs,omitempty"`
}

// Project holds information about a project
type Project struct {
	Metadata
	Inputs  map[string]ProjectInput  `json:"inputs,omitempty"`
	Outputs map[string]ProjectOutput `json:"outputs,omitempty"`
	Status  map[ProjectStatus]bool   `json:"status,omitempty"`
}

// ProjectInput holds information about a single input of a project
type ProjectInput struct {
	Metadata
	Type           ProjectInputType `json:"type"`
	NormalizedName string           `json:"normalized_name"`
}

// ProjectOutput holds information about a single output of a project
type ProjectOutput struct {
	Metadata
	Status ProjectOutputStatus `json:"status"`
}

// Metadata is generic metadata applicable to a wide variety of types
type Metadata struct {
	Id          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Timestamp   string `json:"timestamp"`
}

// ErrorSessionDoesNotExist is returned when the session doesn't exist
type ErrorSessionDoesNotExist struct{}

func (ErrorSessionDoesNotExist) Error() string {
	return "no existing session"
}

// ErrorDoesNotExist is returned when the object does not exist
type ErrorDoesNotExist struct{ Id string }

func (e ErrorDoesNotExist) Error() string {
	return fmt.Sprintf("the id: %s was not found", e.Id)
}

// ErrorIdAlreadyInUse is returned when the Id is already in use.
type ErrorIdAlreadyInUse struct{ Id string }

func (e ErrorIdAlreadyInUse) Error() string {
	return fmt.Sprintf("the id: %s is already in use", e.Id)
}

// ErrorOngoing is returned when the plan/transformation is ongoing.
type ErrorOngoing struct{ Id string }

func (e ErrorOngoing) Error() string {
	return fmt.Sprintf("the generation for object with id: %s is ongoing", e.Id)
}

// ErrorValidation is returned when the request fails validation.
type ErrorValidation struct{ Reason string }

func (e ErrorValidation) Error() string {
	if e.Reason != "" {
		return e.Reason
	}
	return "failed when trying to validate"
}

// ErrorTokenExpired is returned when the token has expired
type ErrorTokenExpired struct{ Exp int64 }

func (e ErrorTokenExpired) Error() string {
	return fmt.Sprintf("the token expired at %v", time.Unix(e.Exp, 0))
}

// ErrorTokenUnverifiable is returned when the token cannot be verified
type ErrorTokenUnverifiable struct{}

func (e ErrorTokenUnverifiable) Error() string {
	return "the token is unverifiable"
}

// ProjectStatus stores the current project status
type ProjectStatus string

const (
	// ProjectStatusInputSources indicates the project has source folder uploaded
	ProjectStatusInputSources ProjectStatus = "sources"
	// ProjectStatusInputCustomizations indicates the project has customizations folder uploaded
	ProjectStatusInputCustomizations ProjectStatus = "customizations"
	// ProjectStatusInputConfigs indicates the project has configs
	ProjectStatusInputConfigs ProjectStatus = "configs"
	// ProjectStatusInputReference indicates the project has references to workspace level inputs
	ProjectStatusInputReference ProjectStatus = "reference"
	// ProjectStatusPlanning indicates the project is currently generating a plan
	ProjectStatusPlanning ProjectStatus = "planning"
	// ProjectStatusPlan indicates the project has a plan
	ProjectStatusPlan ProjectStatus = "plan"
	// ProjectStatusStalePlan indicates that the inputs have changed after the plan was last generated
	ProjectStatusStalePlan ProjectStatus = "stale_plan"
	// ProjectStatusPlanError indicates that an error occurred during planning
	ProjectStatusPlanError ProjectStatus = "plan_error"
	// ProjectStatusOutputs indicates the project has project artifacts generated
	ProjectStatusOutputs ProjectStatus = "outputs"
)

// ProjectOutputStatus is the status of a project output
type ProjectOutputStatus string

const (
	// ProjectOutputStatusInProgress indicates that the transformation is ongoing
	ProjectOutputStatusInProgress = "transforming"
	// ProjectOutputStatusDoneSuccess indicates that the transformation completed successfully
	ProjectOutputStatusDoneSuccess = "done"
	// ProjectOutputStatusDoneError indicates an error like if the transformation was cancelled or the timeout expired
	ProjectOutputStatusDoneError = "error"
)

// ProjectInputType is the type of the project input
type ProjectInputType string

const (
	// ProjectInputSources is the type for project inputs that are folders containing source code
	ProjectInputSources ProjectInputType = ProjectInputType(ProjectStatusInputSources)
	// ProjectInputCustomizations is the type for project inputs that are folders containing customization files
	ProjectInputCustomizations ProjectInputType = ProjectInputType(ProjectStatusInputCustomizations)
	// ProjectInputConfigs is the type for project inputs that are config files
	ProjectInputConfigs ProjectInputType = ProjectInputType(ProjectStatusInputConfigs)
	// ProjectInputReference is the type for project inputs that are references to workspace level inputs
	ProjectInputReference ProjectInputType = ProjectInputType(ProjectStatusInputReference)
)

// ParseProjectInputType parses the string and returns a project input type if valid
func ParseProjectInputType(s string) (ProjectInputType, error) {
	switch s {
	case string(ProjectInputSources):
		return ProjectInputSources, nil
	case string(ProjectInputCustomizations):
		return ProjectInputCustomizations, nil
	case string(ProjectInputConfigs):
		return ProjectInputConfigs, nil
	case string(ProjectInputReference):
		return ProjectInputReference, nil
	default:
		return "", fmt.Errorf("unknown project input type")
	}
}

// CloudEvent contains the data associated with an event in the Cloud Event spec
type CloudEvent struct {
	SpecVersion     string                 `json:"specversion"`
	Type            string                 `json:"type"`
	Source          string                 `json:"source"`
	Id              string                 `json:"id"`
	Subject         string                 `json:"subject"`
	Time            string                 `json:"time"`
	DataContentType string                 `json:"datacontenttype"`
	Data            map[string]interface{} `json:"data"`
}
