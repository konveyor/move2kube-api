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

package handlers

import (
	"encoding/json"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/konveyor/move2kube-api/internal/authserver"
	"github.com/konveyor/move2kube-api/internal/common"
	"github.com/konveyor/move2kube-api/internal/sessions"
	"github.com/konveyor/move2kube-api/internal/types"
)

// HandleLogin logs the user in and gets the authorization code.
func HandleLogin(w http.ResponseWriter, r *http.Request) {
	logrus := GetLogger(r)
	logrus.Trace("HandleLogin start")
	defer logrus.Trace("HandleLogin end")
	if sessions.IsLoggedIn(r) {
		logrus.Error("the user is already logged in")
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	redirectPath := "/"
	if redirStr := r.URL.Query().Get("redirect_path"); redirStr != "" {
		// validate the redirect_path
		redirURL, err := url.Parse(redirStr)
		if err != nil || redirURL.Host != "" {
			logrus.Errorf("the query parameter `redirect_path` is invalid. Actual: %s", redirStr)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		redirectPath = path.Clean(redirURL.Path)
		if !strings.HasPrefix(redirectPath, "/") || strings.HasPrefix(redirectPath, "/api") || strings.HasPrefix(redirectPath, "/swagger") {
			logrus.Errorf("the query parameter `redirect_path` is invalid. Actual: %s", redirStr)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	}
	// create a new session when logging in
	sessInfo, err := sessions.NewSession(w, r)
	if err != nil {
		logrus.Errorf("error while trying to create a new session. Error: %q", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	// save the redirect_path in the session so we can redirect the user after login
	sessInfo.PostLoginRedirectPath = redirectPath
	if err := sessions.SaveSession(w, r, sessInfo); err != nil {
		logrus.Errorf("failed to save the session. Error: %q", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	logrus.Debug("created a new session during login with the Id: ", sessInfo.Id)
	// redirect the user to the login page
	loginURL := authserver.GetLoginURL(sessInfo.GetCSRFToken())
	logrus.Debugf("redirecting the user to %s for login", loginURL)
	http.Redirect(w, r, loginURL, http.StatusFound)
}

// HandleLoginCallback gets the access and refresh tokens for the user given the authorization code.
func HandleLoginCallback(w http.ResponseWriter, r *http.Request) {
	logrus := GetLogger(r)
	logrus.Trace("HandleLoginCallback start")
	defer logrus.Trace("HandleLoginCallback end")
	if sessions.IsLoggedIn(r) {
		logrus.Error("the user is already logged in")
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	// validate the state/CSRF token
	actualCSRFToken := r.URL.Query().Get("state")
	if actualCSRFToken == "" {
		logrus.Errorf("the query parameter `state` is missing. Actual: %s", r.URL.RawQuery)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	sessInfo, err := sessions.GetSession(r)
	if err != nil {
		logrus.Debug(err)
		if _, ok := err.(types.ErrorSessionDoesNotExist); ok {
			logrus.Error("The user is trying to login without an existing session")
			w.Header().Set(common.AUTHENTICATE_HEADER, common.AUTHENTICATE_HEADER_MSG)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		logrus.Errorf("failed to get the session. Error: %q", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if !sessInfo.IsValidCSRFToken(actualCSRFToken) {
		logrus.Debugf("Expected: %s Actual: %s", sessInfo.GetCSRFToken(), actualCSRFToken)
		logrus.Errorf("the CSRF token doesn't match")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// check for errors returned by the authorization server
	if authFlowError := r.URL.Query().Get("error"); authFlowError != "" {
		if authFlowErrorDesc := r.URL.Query().Get("error_description"); authFlowErrorDesc != "" {
			authFlowError = authFlowError + " . Description: " + authFlowErrorDesc
		}
		if authFlowErrorURL := r.URL.Query().Get("error_uri"); authFlowErrorURL != "" {
			authFlowError = authFlowError + " . More Info: " + authFlowErrorURL
		}
		logrus.Errorf("user failed to authenticate or denied consent. Error: %q", authFlowError)
		w.WriteHeader(http.StatusForbidden)
		return
	}
	// get the authorization code
	authCode := r.URL.Query().Get("code")
	if authCode == "" {
		logrus.Error("the query parameter `code` is missing.")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// get the access and refresh tokens using the authorization code
	tokens, err := authserver.GetTokensUsingAuthCode(authCode, common.Config.CurrentHost+common.LOGIN_CALLBACK_PATH, common.Config.M2kClientClientId, common.Config.M2kClientClientSecret)
	if err != nil {
		logrus.Errorf("failed to get the tokens using the authorization code. Error: %q", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	sessInfo.Tokens = tokens
	// get the user's profile information
	userInfo, err := authserver.GetUserInfo(tokens.AccessToken)
	if err != nil {
		logrus.Errorf("failed to get the user information from the authorization server. Error: %q", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	logrus.Debugf("LoginCallback userInfo: %+v", userInfo)
	if userInfo.Sub != nil {
		logrus.Debugf("LoginCallback userInfo subject: %s", *userInfo.Sub)
	}
	if userInfo.PreferredUsername != nil {
		logrus.Debugf("LoginCallback userInfo preferred username: %s", *userInfo.PreferredUsername)
	}
	if userInfo.Email != nil {
		logrus.Debugf("LoginCallback userInfo email: %s", *userInfo.Email)
	}
	sessInfo.User = userInfo
	redirectPath := sessInfo.PostLoginRedirectPath
	sessInfo.PostLoginRedirectPath = ""
	// save the tokens and user information in the session information
	if err := sessions.SaveSession(w, r, sessInfo); err != nil {
		logrus.Errorf("failed to save the session to the store. Error: %q", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	// redirect the user back to where they started the login flow
	http.Redirect(w, r, redirectPath, http.StatusFound)
}

// HandleLogout logs out the user.
func HandleLogout(w http.ResponseWriter, r *http.Request) {
	logrus := GetLogger(r)
	logrus.Trace("HandleLogout start")
	defer logrus.Trace("HandleLogout end")
	if !sessions.IsLoggedIn(r) {
		logrus.Error("The user is trying to logout without logging in")
		w.Header().Set(common.AUTHENTICATE_HEADER, common.AUTHENTICATE_HEADER_MSG)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	logrus.Debug("user is trying to logout")
	sessInfo, err := sessions.GetSession(r)
	if err != nil {
		if _, ok := err.(types.ErrorSessionDoesNotExist); ok {
			logrus.Error("The user is trying to logout without an existing session")
			w.Header().Set(common.AUTHENTICATE_HEADER, common.AUTHENTICATE_HEADER_MSG)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		logrus.Debugf("error while trying to get the session. Error: %q", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	redirectURL, err := url.Parse(common.Config.OIDCInfo.EndSessionEndpoint)
	if err != nil {
		logrus.Errorf("the end session endpoint is not a valid URL. Actual: %s Error: %q", common.Config.OIDCInfo.EndSessionEndpoint, err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	redirectURL.Scheme = ""
	redirectURL.Host = ""
	q := redirectURL.Query()
	q.Set("id_token_hint", sessInfo.Tokens.IdToken)
	q.Set("post_logout_redirect_uri", common.Config.CurrentHost+"/")
	redirectURL.RawQuery = q.Encode()
	// clear tokens from session
	sessInfo.Tokens.AccessToken = ""
	sessInfo.Tokens.IdToken = ""
	sessInfo.Tokens.RefreshToken = ""
	sessInfo.User = types.UserInfo{}
	if err := sessions.SaveSession(w, r, sessInfo); err != nil {
		logrus.Debugf("error while trying to save the session. Error: %q", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

// HandleUserProfile is the handler for getting the user profile
func HandleUserProfile(w http.ResponseWriter, r *http.Request) {
	logrus := GetLogger(r)
	logrus.Trace("HandleUserProfile start")
	defer logrus.Trace("HandleUserProfile end")
	if !sessions.IsLoggedIn(r) {
		logrus.Error("the user is trying to get the user profile information without logging in")
		w.Header().Set(common.AUTHENTICATE_HEADER, common.AUTHENTICATE_HEADER_MSG)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	sessInfo, err := sessions.GetSession(r)
	if err != nil {
		if _, ok := err.(types.ErrorSessionDoesNotExist); ok {
			logrus.Error("the user is trying to get the user profile without an existing session")
			w.Header().Set(common.AUTHENTICATE_HEADER, common.AUTHENTICATE_HEADER_MSG)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		logrus.Debugf("failed to get the session. Error: %q", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	userInfo := types.UserInfo{
		PreferredUsername: sessInfo.User.PreferredUsername,
		Email:             sessInfo.User.Email,
		Picture:           sessInfo.User.Picture,
	}
	w.Header().Set(common.CONTENT_TYPE_HEADER, common.CONTENT_TYPE_JSON)
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(userInfo); err != nil {
		logrus.Errorf("failed to write the response. Error: %q", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}
