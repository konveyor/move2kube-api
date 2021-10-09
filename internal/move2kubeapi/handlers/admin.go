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
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/konveyor/move2kube-api/internal/common"
)

// HandleGetAccessToken handles access token requests
func HandleGetAccessToken(w http.ResponseWriter, r *http.Request) {
	logrus := GetLogger(r)
	logrus.Trace("HandleGetAccessToken start")
	defer logrus.Trace("HandleGetAccessToken end")
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		logrus.Debug("failed to get the access token. The Authorization header is missing.")
		w.Header().Set(common.AUTHENTICATE_HEADER, `Basic realm="Access to the Move2Kube API token endpoint."`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	authHeaderParts := strings.Split(authHeader, " ")
	if len(authHeaderParts) != 2 || authHeaderParts[0] != "Basic" {
		logrus.Debug("failed to get the access token. Expected Basic scheme in Authorization header. Actual", authHeaderParts)
		sendErrorJSON(w, "the Authorization header does not have the correct format. Expected: \"Basic: base64(client_id:client_secret)\"", http.StatusBadRequest)
		return
	}
	clientIDAndSecretBytes, err := base64.StdEncoding.DecodeString(authHeaderParts[1])
	if err != nil {
		logrus.Debug("failed to get the access token. Failed to decode the base64url encoded username and password. Error:", err)
		sendErrorJSON(w, "the Authorization header does not have the correct format. Expected: \"Basic: base64(client_id:client_secret)\"", http.StatusBadRequest)
		return
	}
	clientIDAndSecret := strings.Split(string(clientIDAndSecretBytes), ":")
	if len(clientIDAndSecret) != 2 {
		logrus.Debug("failed to get the access token. Expected username:password. Actual:", clientIDAndSecret)
		sendErrorJSON(w, "the Authorization header does not have the correct format. Expected: \"Basic: base64(client_id:client_secret)\"", http.StatusBadRequest)
		return
	}
	clientID := clientIDAndSecret[0]
	clientSecret := clientIDAndSecret[1]

	token, err := common.AuthServerClient.LoginClient(context.TODO(), clientID, clientSecret, common.Config.AuthServerRealm)
	if err != nil {
		logrus.Errorf("failed to get the access token from the authz server. Error: %q", err)
		w.WriteHeader(http.StatusForbidden)
		return
	}
	body, err := json.Marshal(token)
	if err != nil {
		logrus.Errorf("failed to marshal the access token to json. Error: %q", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set(common.CONTENT_TYPE_HEADER, common.CONTENT_TYPE_JSON)
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(body); err != nil {
		logrus.Errorf("failed to send the access token. Error: %q", err)
		return
	}
}
