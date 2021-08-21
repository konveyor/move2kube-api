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
	"net/http"
	"path"
	"strings"

	"github.com/konveyor/move2kube-api/internal/authserver"
	"github.com/konveyor/move2kube-api/internal/common"
	"github.com/konveyor/move2kube-api/internal/sessions"
	"github.com/konveyor/move2kube-api/internal/types"
	"github.com/sirupsen/logrus"
)

// GetLoggingMiddleWare returns the middleware that logs each request method and URL
func GetLoggingMiddleWare(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logrus.Infof("%s %s", r.Method, r.URL)
		next.ServeHTTP(w, r)
	})
}

// GetAuthorizationMiddleWare returns the middleware that checks for authorization
func GetAuthorizationMiddleWare(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logrus.Trace("GetAuthorizationMiddleWare start")
		resPath := path.Clean(r.URL.Path)
		resPath = strings.TrimPrefix(resPath, "/api/v1")
		if resPath == "" || resPath == "/" || resPath == "." {
			logrus.Warnf("after cleaning the resPath is: '%s'", resPath)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		verb := r.Method
		logrus.Debug("trying to access the resource at path:", resPath, "with the verb:", verb)
		// "/token" has its own authentication/authorization.
		// "/support" is general information about the deployment, useful for debugging.
		if (verb == "GET" && resPath == "/support") ||
			(verb == "POST" && resPath == "/token") {
			logrus.Debugf("authz exception for %s", resPath)
			next.ServeHTTP(w, r)
			return
		}

		accessToken := ""
		if authzHeader := r.Header.Get(common.AUTHZ_HEADER); authzHeader != "" {
			if !strings.HasPrefix(authzHeader, "Bearer ") {
				logrus.Debug("the authz header is invalid. Expected: Bearer <access token> . Actual:", authzHeader)
				sendErrorJSON(w, "the authz header is invalid.", http.StatusBadRequest)
				return
			}
			accessToken = strings.TrimPrefix(authzHeader, "Bearer ")
		} else {
			// if they didn't provide the access token, we check if they have an active session and get the token from the session
			session, err := sessions.GetSession(r)
			if err != nil || session.Tokens.AccessToken == "" {
				if err != nil {
					logrus.Debugf("failed to get the user session. Error: %q", err)
				} else {
					logrus.Debug("the user is not logged in. The session doesn't have any access token")
				}
				w.Header().Set(common.AUTHENTICATE_HEADER, common.AUTHENTICATE_HEADER_MSG)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if !session.RefreshUserTokensIfExpired() {
				logrus.Debug("the user's refresh token expired.")
				w.Header().Set(common.AUTHENTICATE_HEADER, common.AUTHENTICATE_HEADER_MSG)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			accessToken = session.Tokens.AccessToken
			r.Header.Set(common.AUTHZ_HEADER, "Bearer "+accessToken)
		}

		// "GET" on "/workspaces" allows a user to list workspaces they have access to.
		if verb == "GET" && resPath == "/workspaces" {
			logrus.Debugf("authz exception for %s", resPath)
			next.ServeHTTP(w, r)
			return
		}

		// check the cache
		// cacheKey := accessToken + "$" + r.Method + "$" + resPath
		// if rpt, ok := RPTCache[cacheKey]; ok {
		// 	if _, err := decodeToken(rpt, serverJWK); err == nil {
		// 		next.ServeHTTP(w, r)
		// 		return
		// 	}
		// 	delete(RPTCache, cacheKey) // delete invalid RPTs from the cache
		// }

		reqPerms := []types.PermRequest{{ResourceId: common.Config.DefaultResourceId, ResourceScopes: []string{verb}}}
		// resource server
		serverAccessToken, err := authserver.GetResourceServerAccessToken()
		if err != nil {
			logrus.Debugf("failed to get the resource server access token. Error: %q", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		permTicket, err := common.GetPermissionTicket(common.Config.UMAInfo.PermissionEndpoint, reqPerms, serverAccessToken)
		if err != nil {
			logrus.Debugf("failed to get the permission ticket. Error: %q", err)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		// client on behalf of the user (requesting party)
		rpt, err := common.GetUserRPT(permTicket.Ticket, accessToken, resPath)
		if err != nil {
			// try again with a slash at the end
			rpt, err = common.GetUserRPT(permTicket.Ticket, accessToken, resPath+"/")
			if err != nil {
				logrus.Debugf("failed to get the RPT. Error: %q", err)
				w.WriteHeader(http.StatusForbidden)
				return
			}
		}

		// save in cache for later
		// RPTCache[cacheKey] = rpt.AccessToken
		logrus.Debugf("got authorization for user to access protected resources. RPT: %+v", rpt)
		logrus.Trace("GetAuthorizationMiddleWare end")
		next.ServeHTTP(w, r)
	})
}

// GetRemoveTrailingSlashMiddleWare returns the middleware that removes trailing slashes from the request URL
func GetRemoveTrailingSlashMiddleWare(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			r.URL.RawPath = strings.TrimSuffix(r.URL.RawPath, "/")
			r.URL.Path = strings.TrimSuffix(r.URL.Path, "/")
		}
		next.ServeHTTP(w, r)
	})
}
