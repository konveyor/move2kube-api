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
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/go-jose/go-jose/v3"
	"github.com/konveyor/move2kube-api/internal/types"
	"github.com/sirupsen/logrus"
)

// GetTokenUsingRefreshToken gets a new access token using the refresh token
func GetTokenUsingRefreshToken(tokenEndpoint, refreshToken, basicAuth string) (types.Tokens, error) {
	tokens := types.Tokens{}
	q := url.Values{}
	q.Set("grant_type", "refresh_token")
	q.Set("refresh_token", refreshToken)
	req, err := http.NewRequest("POST", tokenEndpoint, bytes.NewBufferString(q.Encode()))
	if err != nil {
		return tokens, err
	}
	req.Header.Set(AUTHZ_HEADER, "Basic "+basicAuth)
	req.Header.Set(CONTENT_TYPE_HEADER, CONTENT_TYPE_FORM_URL_ENCODED)
	logrus.Debugf("going to send the refresh request: %+v\n", req)
	resp, err := new(http.Client).Do(req)
	if err != nil {
		return tokens, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		if resp.StatusCode == http.StatusUnauthorized {
			logrus.Debugf("%s %s", AUTHENTICATE_HEADER, resp.Header.Get(AUTHENTICATE_HEADER))
		}
		logrus.Debug("the refresh access token request failed")
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return tokens, err
		}
		return tokens, fmt.Errorf("%s\n%s", resp.Status, string(bodyBytes))
	}
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return tokens, err
	}
	// logrus.Debug("getTokenUsingClientCreds bodyBytes: ", string(bodyBytes))
	if err := json.Unmarshal(bodyBytes, &tokens); err != nil {
		return tokens, err
	}
	return tokens, nil
}

// GetTokenUsingClientCreds gets a new access token using the client credentials
func GetTokenUsingClientCreds(tokenEndpoint, clientId, clientSecret string) (types.Tokens, error) {
	tokens := types.Tokens{}
	q := url.Values{}
	q.Set("grant_type", "client_credentials")
	req, err := http.NewRequest("POST", tokenEndpoint, bytes.NewBufferString(q.Encode()))
	if err != nil {
		return tokens, fmt.Errorf("failed to create a POST request for the token endpoint %s . Error: %q", tokenEndpoint, err)
	}
	req.Header.Set(AUTHZ_HEADER, "Basic "+base64.StdEncoding.EncodeToString([]byte(clientId+":"+clientSecret)))
	req.Header.Set(CONTENT_TYPE_HEADER, CONTENT_TYPE_FORM_URL_ENCODED)
	logrus.Debugf("going to send the request: %+v\n", req)
	resp, err := new(http.Client).Do(req)
	if err != nil {
		return tokens, fmt.Errorf("failed to send the POST request to the token endpoint %s . Error: %q", tokenEndpoint, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		if resp.StatusCode == http.StatusUnauthorized {
			logrus.Debugf("%s %s", AUTHENTICATE_HEADER, resp.Header.Get(AUTHENTICATE_HEADER))
		}
		logrus.Debugf("the client credentials access token request failed %s\n", resp.Status)
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return tokens, fmt.Errorf("failed to read the response body. Error: %q", err)
		}
		return tokens, fmt.Errorf("the POST request for access token returned a error status code. Status: %s . Error: %s", resp.Status, string(bodyBytes))
	}
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return tokens, fmt.Errorf("failed to read the response body. Error: %q", err)
	}
	// logrus.Debug("getTokenUsingClientCreds bodyBytes: ", string(bodyBytes))
	if err := json.Unmarshal(bodyBytes, &tokens); err != nil {
		return tokens, fmt.Errorf("failed to unmarshal the response body as json. Error: %q", err)
	}
	return tokens, nil
}

// GetPermissionTicket gets a new permission ticket for use with the UMA grant flow
func GetPermissionTicket(permEndpoint string, reqPerms []types.PermRequest, serverPAT string) (types.PermTicket, error) {
	ticket := types.PermTicket{}
	reqBytes, err := json.Marshal(reqPerms)
	if err != nil {
		return ticket, fmt.Errorf("failed to marshal the request permissions to json. Error: %q", err)
	}
	req, err := http.NewRequest("POST", permEndpoint, bytes.NewBuffer(reqBytes))
	if err != nil {
		return ticket, fmt.Errorf("failed to create a POST request for the permissions endpoint at %s with the request body: %s\nError: %q", permEndpoint, string(reqBytes), err)
	}
	req.Header.Set(AUTHZ_HEADER, "Bearer "+serverPAT)
	req.Header.Set(CONTENT_TYPE_HEADER, CONTENT_TYPE_JSON)
	logrus.Debugf("about to make perm ticket request %+v\n", req)
	resp, err := new(http.Client).Do(req)
	if err != nil {
		return ticket, fmt.Errorf("failed to send the POST request to the permissions endpoint at %s . Error: %q", permEndpoint, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		logrus.Debug("the permission ticket request failed")
		if resp.StatusCode == http.StatusUnauthorized {
			logrus.Debugf("%s %s", AUTHENTICATE_HEADER, resp.Header.Get(AUTHENTICATE_HEADER))
		}
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return ticket, fmt.Errorf("failed to read the permission ticket response body. Error: %q", err)
		}
		return ticket, fmt.Errorf("failed to get the permission ticket. Status: %s Error: %s", resp.Status, string(bodyBytes))
	}
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return ticket, fmt.Errorf("failed to read the permission ticket response body. Error: %q", err)
	}
	// logrus.Debug("getPermissionTicket bodyBytes: ", string(bodyBytes))
	if err := json.Unmarshal(bodyBytes, &ticket); err != nil {
		return ticket, fmt.Errorf("failed to unmarshal the permission ticket request from json. Error: %q", err)
	}
	return ticket, nil
}

func getClaimToken(resPath string) string {
	x := map[string][]string{"resource_path": {resPath}}
	y, err := json.Marshal(x)
	if err != nil {
		logrus.Errorf("failed to marshal the resource path claim to json. Error: %q", err)
		return ""
	}
	return base64.StdEncoding.EncodeToString(y)
}

// GetUserRPT tries to get a Relying Party Token (RPT) fromt the authorization server using the UMA grant flow
func GetUserRPT(permTicket string, userAccessToken string, resPath string) (types.Tokens, error) {
	tokens := types.Tokens{}
	q := url.Values{}
	q.Set("grant_type", "urn:ietf:params:oauth:grant-type:uma-ticket")
	q.Set("ticket", permTicket)
	claimToken := getClaimToken(resPath)
	q.Set("claim_token", claimToken)
	q.Set("claim_token_format", "urn:ietf:params:oauth:token-type:jwt")
	req, err := http.NewRequest("POST", Config.OIDCInfo.TokenEndpoint, bytes.NewBufferString(q.Encode()))
	if err != nil {
		return tokens, err
	}
	req.Header.Set(AUTHZ_HEADER, "Bearer "+userAccessToken)
	req.Header.Set(CONTENT_TYPE_HEADER, CONTENT_TYPE_FORM_URL_ENCODED)
	resp, err := new(http.Client).Do(req)
	if err != nil {
		return tokens, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		if resp.StatusCode == http.StatusUnauthorized {
			logrus.Debugf("%s %s", AUTHENTICATE_HEADER, resp.Header.Get(AUTHENTICATE_HEADER))
		}
		logrus.Debug("the rpt token request failed")
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return tokens, err
		}
		err = fmt.Errorf("%s\n%s", resp.Status, string(bodyBytes))
		logrus.Debug(err)
		return types.Tokens{}, err
	}
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return tokens, err
	}
	// logrus.Debug("getUserRPT bodyBytes: ", string(bodyBytes))
	if err := json.Unmarshal(bodyBytes, &tokens); err != nil {
		return tokens, err
	}
	return tokens, nil
}

// GetAllJWKs returns all the JSON web keys that the server uses
func GetAllJWKs(jwkURL string) (map[string]jose.JSONWebKey, error) {
	resp, err := http.Get(jwkURL)
	if err != nil {
		return nil, fmt.Errorf("failed to send the GET request to the jwks_uri %s . Error: %q", jwkURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("got an error status code from the jwks_uri %s . Status: %s", jwkURL, resp.Status)
	}
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read the response body. Error: %q", err)
	}
	jwkKeyInfo := struct{ Keys []map[string]interface{} }{}
	if err := json.Unmarshal(bodyBytes, &jwkKeyInfo); err != nil {
		return nil, fmt.Errorf("failed to unmarshal the keys as json. Error: %q", err)
	}
	results := map[string]jose.JSONWebKey{}
	for _, key := range jwkKeyInfo.Keys {
		jwk := jose.JSONWebKey{}
		keyBytes, err := json.Marshal(key)
		if err != nil {
			logrus.Errorf("failed to marshal the key %+v back to json. Error: %q", key, err)
			continue
		}
		if err := jwk.UnmarshalJSON(keyBytes); err != nil {
			logrus.Errorf("failed to unmarshal the json %s as json web key. Error: %q", string(keyBytes), err)
			continue
		}
		results[jwk.KeyID] = jwk
	}
	return results, nil
}
