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
	"fmt"
	"net/http"
	"path/filepath"

	"github.com/konveyor/move2kube-api/internal/authserver"
	"github.com/konveyor/move2kube-api/internal/common"
	"github.com/konveyor/move2kube-api/internal/filesystem"
	"github.com/konveyor/move2kube-api/internal/sessions"
	"github.com/sirupsen/logrus"
)

const (
	// DEBUG_QUERY_PARAM is the name of the query parameter used for debug mode
	DEBUG_QUERY_PARAM = "debug"
	// WORKSPACE_ID_ROUTE_VAR is the route variable that contains the workspace Id
	WORKSPACE_ID_ROUTE_VAR = "work-id"
	// PROJECT_ID_ROUTE_VAR is the route variable that contains the project Id
	PROJECT_ID_ROUTE_VAR = "proj-id"
	// PROJECT_INPUT_ID_ROUTE_VAR is the route variable that contains the project input Id
	PROJECT_INPUT_ID_ROUTE_VAR = "input-id"
	// PROJECT_OUTPUT_ID_ROUTE_VAR is the route variable that contains the project output Id
	PROJECT_OUTPUT_ID_ROUTE_VAR = "output-id"
	// ROLE_ID_ROUTE_VAR is the route variable that contains the role Id
	ROLE_ID_ROUTE_VAR = "role-id"
	// IDP_USER_ID_ROUTE_VAR is the route variable for the user id
	IDP_USER_ID_ROUTE_VAR = "user-id"
)

var (
	m2kFS filesystem.IFileSystem
)

// Setup handlers
func Setup() error {
	logrus.Trace("Setup start")
	defer logrus.Trace("Setup end")
	absDataDir, err := filepath.Abs(common.Config.DataDir)
	if err != nil {
		return fmt.Errorf("failed to make the data directory path %s absolute. Error: %q", common.Config.DataDir, err)
	}
	common.Config.DataDir = absDataDir
	logrus.Debug("creating the filesystem object")
	m2kFS = filesystem.NewFileSystem()
	if common.Config.AuthEnabled {
		if err := authserver.Setup(); err != nil {
			return fmt.Errorf("failed to setup the OIDC info. Error: %q", err)
		}
		if err := sessions.SetupSessionStore(); err != nil {
			return fmt.Errorf("failed to setup the session store. Error: %q", err)
		}
	}
	return nil
}

// HandleSupport is the handler for getting support information
func HandleSupport(w http.ResponseWriter, r *http.Request) {
	logrus := GetLogger(r)
	logrus.Trace("HandleSupport start")
	supportInfo := m2kFS.GetSupportInfo()
	w.Header().Set(common.CONTENT_TYPE_HEADER, common.CONTENT_TYPE_JSON)
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(supportInfo); err != nil {
		logrus.Errorf("failed to send the response. Error: %q", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	logrus.Trace("HandleSupport end")
}

func sendErrorJSON(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set(common.CONTENT_TYPE_HEADER, common.CONTENT_TYPE_JSON)
	w.WriteHeader(statusCode)
	errMsg := map[string]interface{}{"error": map[string]string{"description": message}}
	errBytes, err := json.Marshal(errMsg)
	if err != nil {
		logrus.Errorf("failed to marshal the error message to json. Error: %q", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if _, err := w.Write(errBytes); err != nil {
		logrus.Errorf("failed to write the error message to the response. Error: %q", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}
