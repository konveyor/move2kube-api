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

package authserver

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/Nerzal/gocloak/v8"
	"github.com/go-jose/go-jose/v3"
	"github.com/go-resty/resty/v2"
	"github.com/konveyor/move2kube-api/internal/common"
	"github.com/konveyor/move2kube-api/internal/types"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cast"
)

const (
	// URL_READ_WORKSPACE is the endpoint used to read a workspace
	URL_READ_WORKSPACE = "/workspaces/%s" // %s should be filled with workspace id
	// VERB_ALL_PERMS is the verb that allows all actions on the resource
	VERB_ALL_PERMS = "all"
	// VERB_READ_WORKSPACE is the verb that allows read permission on a workspace
	VERB_READ_WORKSPACE = "GET"
)

var (
	serverTokens types.Tokens
	serverJWKs   map[string]jose.JSONWebKey
)

// Setup sets up the authorization server.
func Setup() (err error) {
	common.AuthServerClient = gocloak.NewClient(
		common.Config.AuthServer+common.Config.AuthServerBasePath,
		gocloak.SetAuthRealms("realms"),
		gocloak.SetAuthAdminRealms("admin/realms"),
	)
	discoveryEndpointPath := common.Config.OIDCDiscoveryEndpointPath
	if discoveryEndpointPath == "" {
		discoveryEndpointPath = fmt.Sprintf(common.OIDC_DISCOVERY_ENDPOINT_PATH, common.Config.AuthServerRealm)
	}
	discoveryEndpoint := common.Config.AuthServer + common.Config.AuthServerBasePath + discoveryEndpointPath
	common.Config.OIDCInfo, err = GetOIDCInfo(discoveryEndpoint)
	if err != nil {
		return fmt.Errorf("failed to get the OIDC information from the authorization server endpoint %s . Error: %q", discoveryEndpoint, err)
	}
	umaConfigEndpointPath := common.Config.UMAConfigurationEndpointPath
	if umaConfigEndpointPath == "" {
		umaConfigEndpointPath = fmt.Sprintf(common.UMA_CONFIGURATION_ENDPOINT_PATH, common.Config.AuthServerRealm)
	}
	umaConfigEndpoint := common.Config.AuthServer + common.Config.AuthServerBasePath + umaConfigEndpointPath
	common.Config.UMAInfo, err = GetUMAInfo(umaConfigEndpoint)
	if err != nil {
		return fmt.Errorf("failed to get the UMA configuration information from the authorization server endpoint %s . Error: %q", umaConfigEndpoint, err)
	}
	logrus.Debug("added OIDC and UMA information to the config:\n", common.Config)
	serverJWKs, err = common.GetAllJWKs(common.Config.OIDCInfo.JwksURI)
	if err != nil {
		return fmt.Errorf("failed to get the authorization server public keys. Error: %q", err)
	}
	serverTokens, err = common.GetTokenUsingClientCreds(common.Config.OIDCInfo.TokenEndpoint, common.Config.M2kServerClientId, common.Config.M2kServerClientSecret)
	if err != nil {
		return fmt.Errorf("failed to get the resource server access token. Error: %q", err)
	}
	return nil
}

// DecodeToken decodes the token using the JSON web keys from the server
func DecodeToken(token string) ([]byte, error) {
	return common.DecodeToken(token, serverJWKs)
}

// GetResourceServerAccessToken returns the access token for the resource server
func GetResourceServerAccessToken() (string, error) {
	if err := refreshServerTokensIfExpired(); err != nil {
		return serverTokens.AccessToken, fmt.Errorf("failed to refresh the resource server access token. Error: %q", err)
	}
	return serverTokens.AccessToken, nil
}

func refreshServerTokensIfExpired() error {
	if _, err := DecodeToken(serverTokens.AccessToken); err != nil {
		logrus.Debug("resource server access token expired. refreshing...")
		serverTokens, err = common.GetTokenUsingClientCreds(common.Config.OIDCInfo.TokenEndpoint, common.Config.M2kServerClientId, common.Config.M2kServerClientSecret)
		if err != nil {
			return fmt.Errorf("failed to get the resource server access token. Error: %q", err)
		}
	} else {
		logrus.Debug("resource server access token is still valid.")
	}
	return nil
}

// GetOIDCInfo gets the OIDC information from the authorization server.
func GetOIDCInfo(discoveryEndpoint string) (types.OIDCInfo, error) {
	oidcInfo := types.OIDCInfo{}
	resp, err := http.Get(discoveryEndpoint)
	if err != nil {
		return oidcInfo, fmt.Errorf("failed to get the OIDC information from the server. Error: %q", err)
	}
	defer resp.Body.Close()
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return oidcInfo, fmt.Errorf("failed to read the OIDC information from the response body. Error: %q", err)
	}
	if err := json.Unmarshal(bodyBytes, &oidcInfo); err != nil {
		return oidcInfo, fmt.Errorf("failed to unmarshal the OIDC information as json. Error: %q", err)
	}
	return oidcInfo, nil
}

// GetUMAInfo gets the UMA information from the authorization server.
func GetUMAInfo(umaConfigEndpoint string) (types.UMAInfo, error) {
	umaInfo := types.UMAInfo{}
	resp, err := http.Get(umaConfigEndpoint)
	if err != nil {
		return umaInfo, fmt.Errorf("failed to get the UMA configuration information from the server. Error: %q", err)
	}
	defer resp.Body.Close()
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return umaInfo, fmt.Errorf("failed to read the UMA configuration information from the response body. Error: %q", err)
	}
	if err := json.Unmarshal(bodyBytes, &umaInfo); err != nil {
		return umaInfo, fmt.Errorf("failed to unmarshal the UMA configuration information as json. Error: %q", err)
	}
	return umaInfo, nil
}

// GetTokensUsingAuthCode gets access and refresh tokens according to https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
func GetTokensUsingAuthCode(authCode, redirectURI, clientID, clientSecret string) (types.Tokens, error) {
	tokens := types.Tokens{}
	// prepare the request
	reqParams := url.Values{}
	reqParams.Set("grant_type", "authorization_code")
	reqParams.Set("code", authCode)
	reqParams.Set("redirect_uri", redirectURI)
	reqBody := bytes.NewBufferString(reqParams.Encode())
	tokenEndpoint := common.Config.OIDCInfo.TokenEndpoint
	reqBasicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(clientID+":"+clientSecret))

	req, err := http.NewRequest("POST", tokenEndpoint, reqBody)
	if err != nil {
		return tokens, fmt.Errorf("failed to prepare a POST request for the token endpoint %s . Error: %q", tokenEndpoint, err)
	}
	req.Header.Set(common.AUTHZ_HEADER, reqBasicAuth)
	req.Header.Set(common.CONTENT_TYPE_HEADER, common.CONTENT_TYPE_FORM_URL_ENCODED)

	logrus.Debugf("going to send the access token request using authorization_code flow. Request: %+v", req)
	// send the request
	resp, err := new(http.Client).Do(req)
	if err != nil {
		return tokens, fmt.Errorf("failed to send a POST request to the token endpoint %s . Error: %q", tokenEndpoint, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode > 299 {
		getTokenError := ""
		if resp.StatusCode == 400 {
			if bodyBytes, err := ioutil.ReadAll(resp.Body); err == nil {
				errInfo := map[string]interface{}{}
				if err := json.Unmarshal(bodyBytes, &errInfo); err == nil {
					if t2I, ok := errInfo["error"]; ok {
						if t2, ok := t2I.(string); ok {
							getTokenError = getTokenError + " . Error: " + t2
						}
					}
					if t2I, ok := errInfo["error_description"]; ok {
						if t2, ok := t2I.(string); ok {
							getTokenError = getTokenError + " . Description: " + t2
						}
					}
					if t2I, ok := errInfo["error_uri"]; ok {
						if t2, ok := t2I.(string); ok {
							getTokenError = getTokenError + " . More Info: " + t2
						}
					}
				}
			}
		}
		return tokens, fmt.Errorf("the POST request to the token endpoint %s returned an error status code. Status: %s%s", tokenEndpoint, resp.Status, getTokenError)
	}
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return tokens, fmt.Errorf("failed to read the response from the token endpoint %s . Error: %q", tokenEndpoint, err)
	}
	logrus.Debugf("GetTokensUsingAuthCode string(bodyBytes): %s", string(bodyBytes))
	if err := json.Unmarshal(bodyBytes, &tokens); err != nil {
		return tokens, fmt.Errorf("failed to unmarshal the response from the token endpoint as json. Error: %q", err)
	}
	return tokens, nil
}

// GetLoginURL returns the URL of the authz server frontend to which the user should be redirected for login
func GetLoginURL(csrfToken string) string {
	authServerURL, _ := url.Parse(common.Config.OIDCInfo.AuthorizationEndpoint)
	authServerURL.Scheme = ""
	authServerURL.Host = ""
	q := authServerURL.Query()
	q.Set("response_type", "code")
	q.Set("scope", "openid profile email")
	q.Set("client_id", common.Config.M2kClientClientId)
	q.Set("redirect_uri", common.Config.CurrentHost+common.LOGIN_CALLBACK_PATH)
	q.Set("state", csrfToken)
	authServerURL.RawQuery = q.Encode()
	return authServerURL.String()
}

// GetUserInfo retrieves the user's information from the authz server, given the user's access token
func GetUserInfo(accessToken string) (types.UserInfo, error) {
	user, err := common.AuthServerClient.GetUserInfo(context.TODO(), accessToken, common.Config.AuthServerRealm)
	if err != nil {
		return types.UserInfo{}, fmt.Errorf("failed to get the user profile from the authz server. Error: %q", err)
	}
	return types.UserInfo(*user), err
}

// GetUserInfoFromOIDC returns the user's identifying information from the OIDC user info endpoint
func GetUserInfoFromOIDC(accessToken string) (types.UserInfo, error) {
	userInfo := types.UserInfo{}
	req, err := http.NewRequest("GET", common.Config.OIDCInfo.UserinfoEndpoint, nil)
	if err != nil {
		return userInfo, fmt.Errorf("failed to create a GET request to send to the OIDC user info endpoint at %s . Error: %q", common.Config.OIDCInfo.UserinfoEndpoint, err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := new(http.Client).Do(req)
	if err != nil {
		return userInfo, fmt.Errorf("failed to make the GET request to the OIDC user info endpoint at %s . Error: %q", common.Config.OIDCInfo.UserinfoEndpoint, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode > 299 {
		respError := ""
		if resp.StatusCode == 400 {
			if bodyBytes, err := ioutil.ReadAll(resp.Body); err == nil {
				errInfo := map[string]interface{}{}
				if err := json.Unmarshal(bodyBytes, &errInfo); err == nil {
					if t2I, ok := errInfo["error"]; ok {
						if t2, ok := t2I.(string); ok {
							respError = respError + " . Error: " + t2
						}
					}
					if t2I, ok := errInfo["error_description"]; ok {
						if t2, ok := t2I.(string); ok {
							respError = respError + " . Description: " + t2
						}
					}
					if t2I, ok := errInfo["error_uri"]; ok {
						if t2, ok := t2I.(string); ok {
							respError = respError + " . More Info: " + t2
						}
					}
				}
			}
		}
		return userInfo, fmt.Errorf("the GET request to the OIDC user info endpoint %s returned an error status code. Status: %s%s", common.Config.OIDCInfo.UserinfoEndpoint, resp.Status, respError)
	}
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return userInfo, fmt.Errorf("failed to get the user profile from the OIDC user info endpoint. Error: %q", err)
	}
	logrus.Debugf("GetUserInfo string(bodyBytes): %s", string(bodyBytes))
	if err := json.Unmarshal(bodyBytes, &userInfo); err != nil {
		return userInfo, fmt.Errorf("failed to unmarshal the user info as json. Error: %q", err)
	}
	return userInfo, nil
}

// FilterWorkspacesUserHasAccessTo filters the provided workspace Ids and returns only the ones the user has access to
func FilterWorkspacesUserHasAccessTo(workspaceIds []string, accessToken string) ([]string, error) {
	logrus.Trace("FilterWorkspacesUserHasAccessTo start")
	serverAccessToken, err := GetResourceServerAccessToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get the access token for the resource server. Error: %q", err)
	}
	payload, err := DecodeToken(accessToken)
	if err != nil {
		if _, ok := err.(types.ErrorTokenExpired); ok {
			return nil, err
		}
		return nil, fmt.Errorf("failed to decode the access token to get the user roles. Error: %q", err)
	}
	decodedToken := decodedToken{}
	if err := json.Unmarshal(payload, &decodedToken); err != nil {
		return nil, fmt.Errorf("failed to unmarshal the token as json. Error: %q", err)
	}
	if decodedToken.Subject == "" {
		return nil, fmt.Errorf("the access token has an empty 'sub' field")
	}
	if decodedToken.ClientId == "" {
		if decodedToken.AZP == "" {
			return nil, fmt.Errorf("the access token has an empty 'client id' field and an empty 'azp' field")
		}
		decodedToken.ClientId = decodedToken.AZP
	}
	clientIdNotClientId := ""
	if decodedToken.ClientId == common.Config.M2kClientClientId {
		clientIdNotClientId = common.Config.M2kClientIdNotClientId
	} else {
		clients, err := common.AuthServerClient.GetClients(context.TODO(), serverAccessToken, common.Config.AuthServerRealm, gocloak.GetClientsParams{ClientID: &decodedToken.ClientId})
		if err != nil {
			return nil, fmt.Errorf("failed to get the authz server id of the client with OAuth id %s . Error: %q", decodedToken.ClientId, err)
		}
		if len(clients) != 1 {
			return nil, fmt.Errorf("expected exactly one client with the OAuth id. Actual length: %d Actual: %+v", len(clients), clients)
		}
		if clients[0].ID == nil {
			return nil, fmt.Errorf("the authz server id for the client with OAuth id %s is nil", clients)
		}
		clientIdNotClientId = *clients[0].ID
	}
	userRoles, err := GetCompositeClientRolesByUserID(context.TODO(), serverAccessToken, common.Config.AuthServerRealm, clientIdNotClientId, decodedToken.Subject, false)
	if err != nil {
		return nil, fmt.Errorf("failed to get the roles for the user with %s . Error: %q", decodedToken.Subject, err)
	}
	// check for a fake user and get the roles of the fake user as well
	user, err := common.AuthServerClient.GetUserByID(context.TODO(), serverAccessToken, common.Config.AuthServerRealm, decodedToken.Subject)
	if err != nil {
		return nil, fmt.Errorf("failed to get the user attributes. Error: %q", err)
	}
	if user.Username != nil && user.Attributes != nil {
		if idpIdAttr, ok := (*user.Attributes)[common.IDP_ID_ROUTE_VAR]; ok && len(idpIdAttr) == 1 {
			idpId := idpIdAttr[0]
			fakeUserName := idpId + common.DELIM + *user.Username
			users, err := common.AuthServerClient.GetUsers(context.TODO(), serverAccessToken, common.Config.AuthServerRealm, gocloak.GetUsersParams{Username: &fakeUserName})
			if err != nil {
				return nil, fmt.Errorf("failed to get the users with the username %s . Error: %q", fakeUserName, err)
			}
			if len(users) == 1 && users[0] != nil {
				fakeUser := *users[0]
				if fakeUser.ID == nil {
					return nil, fmt.Errorf("the fake user has a nil ID")
				}
				// fakeUser.ClientRoles is usually empty because keycloak only returns a subset of the user's fields
				fakeUserRoles, err := GetCompositeClientRolesByUserID(context.TODO(), serverAccessToken, common.Config.AuthServerRealm, clientIdNotClientId, *fakeUser.ID, false)
				if err != nil {
					return nil, fmt.Errorf("failed to get the client roles for the fake user with username %s and id %s . Error: %q", fakeUserName, *fakeUser.ID, err)
				}
				userRoles = append(userRoles, fakeUserRoles...)
			}
		}
	}
	// filter workspaces user has access to
	filteredIds := []string{}
	if len(userRoles) == 0 {
		logrus.Debug("the user has no roles")
		return filteredIds, nil
	}
	for _, workspaceId := range workspaceIds {
		url := fmt.Sprintf(URL_READ_WORKSPACE, workspaceId)
		if rolesHaveAccess(url+"/", userRoles) || rolesHaveAccess(url, userRoles) { // "/workspaces/work-1/" is same as "/workspaces/work-1"
			filteredIds = append(filteredIds, workspaceId)
		}
	}
	logrus.Trace("FilterWorkspacesUserHasAccessTo end")
	return filteredIds, nil
}

func rolesHaveAccess(url string, roles []*gocloak.Role) bool {
	logrus.Trace("RolesHaveAccess start")
	for i, role := range roles {
		if role == nil {
			logrus.Errorf("the role at index %d is nil", i)
			continue
		}
		if roleHasAccess(url, *role) {
			return true
		}
	}
	logrus.Trace("RolesHaveAccess end")
	return false
}

func roleHasAccess(url string, role gocloak.Role) bool {
	logrus.Trace("RoleHasAccess start")
	if role.Attributes == nil {
		return false
	}
	for pattern, scopes := range *role.Attributes {
		if len(scopes) == 0 {
			continue
		}
		if !patternHasAccess(url, pattern) {
			continue
		}
		for _, scope := range scopes {
			if scope == VERB_ALL_PERMS || scope == VERB_READ_WORKSPACE {
				return true
			}
		}
	}
	logrus.Trace("RoleHasAccess end")
	return false
}

func patternHasAccess(url string, pattern string) bool {
	logrus.Trace("PatternHasAccess start")
	reg, err := regexp.Compile("^" + pattern + "$") // TODO: fix this. The patterns are javascript regexs, NOT golang regexs.
	if err != nil {
		logrus.Errorf("failed to compile the pattern '%s' as a regex. Error: %q", pattern, err)
		return false
	}
	logrus.Trace("PatternHasAccess end")
	return reg.MatchString(url)
}

// GetCompositeClientRolesByUserID is our custom version of GetCompositeClientRolesByUserID
// This is a workaround for this issue https://github.com/Nerzal/gocloak/issues/306
func GetCompositeClientRolesByUserID(ctx context.Context, token, realm, clientID, userID string, briefRepresentation bool) ([]*gocloak.Role, error) {
	const errMessage = "could not get composite client roles by user id"
	var result []*gocloak.Role
	resp, err := getRequestWithBearerAuth(ctx, token).SetResult(&result).SetQueryParam("briefRepresentation", cast.ToString(briefRepresentation)).Get(getAdminRealmURL(realm, "users", userID, "role-mappings", "clients", clientID, "composite"))
	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}
	return result, nil
}

func getRequestWithBearerAuth(ctx context.Context, token string) *resty.Request {
	var err gocloak.HTTPErrorResponse
	return common.AuthServerClient.RestyClient().R().SetContext(ctx).SetError(&err).SetAuthToken(token).SetHeader("Content-Type", "application/json")
}

func getAdminRealmURL(realm string, path ...string) string {
	basePath := strings.TrimRight(common.Config.AuthServer+common.Config.AuthServerBasePath, "/")
	authAdminRealms := "admin/realms"
	path = append([]string{basePath, authAdminRealms, realm}, path...)
	return strings.Join(path, "/")
}

func checkForError(resp *resty.Response, err error, errMessage string) error {
	if err != nil {
		return &gocloak.APIError{
			Code:    0,
			Message: errors.Wrap(err, errMessage).Error(),
			Type:    gocloak.ParseAPIErrType(err),
		}
	}
	if resp == nil {
		return &gocloak.APIError{
			Message: "empty response",
			Type:    gocloak.ParseAPIErrType(err),
		}
	}
	if resp.IsError() {
		var msg string

		if e, ok := resp.Error().(*gocloak.HTTPErrorResponse); ok && e.NotEmpty() {
			msg = fmt.Sprintf("%s: %s", resp.Status(), e)
		} else {
			msg = resp.Status()
		}

		return &gocloak.APIError{
			Code:    resp.StatusCode(),
			Message: msg,
			Type:    gocloak.ParseAPIErrType(err),
		}
	}
	return nil
}

type decodedToken struct {
	AZP            string `json:"azp"`
	ClientId       string `json:"clientId"`
	Subject        string `json:"sub"`
	ResourceAccess map[string]struct {
		Roles []string `json:"roles,omitempty"`
	} `json:"resource_access,omitempty"`
}
