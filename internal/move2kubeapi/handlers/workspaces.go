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

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/konveyor/move2kube-api/internal/authserver"
	"github.com/konveyor/move2kube-api/internal/cloudevents"
	"github.com/konveyor/move2kube-api/internal/common"
	"github.com/konveyor/move2kube-api/internal/sessions"
	"github.com/konveyor/move2kube-api/internal/types"
)

// HandleListWorkspaces handles listing all the workspaces a user has access to
func HandleListWorkspaces(w http.ResponseWriter, r *http.Request) {
	logrus := GetLogger(r)
	logrus.Trace("HandleListWorkspaces start")
	defer logrus.Trace("HandleListWorkspaces end")
	var workspaces []types.Workspace
	if common.Config.AuthEnabled {
		accessToken, err := common.GetAccesTokenFromAuthzHeader(r)
		if err != nil {
			logrus.Errorf("failed to get the access token from the authorization header. Error: %q", err)
			sendErrorJSON(w, "failed to get the access token from the authorization header", http.StatusBadRequest)
			return
		}
		workspaceIds, err := m2kFS.ListWorkspaceIds()
		if err != nil {
			logrus.Errorf("failed to list the workspace ids. Error: %q", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		filteredIds, err := authserver.FilterWorkspacesUserHasAccessTo(workspaceIds, accessToken)
		if err != nil {
			if _, ok := err.(types.ErrorTokenExpired); ok {
				logrus.Errorf("the user access token expired")
				w.Header().Set(common.AUTHENTICATE_HEADER, common.AUTHENTICATE_HEADER_MSG)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			logrus.Errorf("failed to filter the workspace ids the user has access to. Error: %q", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		workspaces, err = m2kFS.ListWorkspaces(filteredIds)
		if err != nil {
			logrus.Errorf("failed to list the workspaces. Error: %q", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	} else {
		var err error
		workspaces, err = m2kFS.ListWorkspaces(nil)
		if err != nil {
			logrus.Errorf("failed to list the workspaces. Error: %q", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}
	w.Header().Set(common.CONTENT_TYPE_HEADER, common.CONTENT_TYPE_JSON)
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(workspaces); err != nil {
		logrus.Errorf("failed to send the workspaces json in the response. Error: %q", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

// HandleCreateWorkspace handles creating a new workspace
func HandleCreateWorkspace(w http.ResponseWriter, r *http.Request) {
	logrus := GetLogger(r)
	logrus.Trace("HandleCreateWorkspace start")
	defer logrus.Trace("HandleCreateWorkspace end")
	defer r.Body.Close()
	reqWorkspace := types.Workspace{}
	if err := json.NewDecoder(r.Body).Decode(&reqWorkspace); err != nil {
		logrus.Errorf("failed to unmarshal the request body as a workspace json. Error: %q", err)
		sendErrorJSON(w, "failed to unmarshal the request body as a workspace json", http.StatusBadRequest)
		return
	}
	timestamp, _, err := common.GetTimestamp()
	if err != nil {
		logrus.Errorf("failed to get the timestamp. Error: %q", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	reqWorkspace.Id = uuid.NewString()
	reqWorkspace.Timestamp = timestamp
	reqWorkspace.ProjectIds = []string{}
	if err := m2kFS.CreateWorkspace(reqWorkspace); err != nil {
		logrus.Errorf("failed to create the workspace %+v . Error: %q", reqWorkspace, err)
		if _, ok := err.(types.ErrorValidation); ok {
			sendErrorJSON(w, "the project given in the request body is invalid", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set(common.CONTENT_TYPE_HEADER, common.CONTENT_TYPE_JSON)
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(map[string]string{"id": reqWorkspace.Id}); err != nil {
		logrus.Errorf("failed to send the response. Error: %q", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

// HandleReadWorkspace handles reading an existing workspace
func HandleReadWorkspace(w http.ResponseWriter, r *http.Request) {
	logrus := GetLogger(r)
	logrus.Trace("HandleReadWorkspace start")
	defer logrus.Trace("HandleReadWorkspace end")
	routeVars := mux.Vars(r)
	workspaceId := routeVars[WORKSPACE_ID_ROUTE_VAR]
	if !common.IsValidId(workspaceId) {
		logrus.Errorf("invalid workspace id. Actual: %s", workspaceId)
		sendErrorJSON(w, "invalid workspace id", http.StatusBadRequest)
		return
	}
	workspace, err := m2kFS.ReadWorkspace(workspaceId)
	if err != nil {
		logrus.Errorf("failed to get the workspace. Error: %q", err)
		if _, ok := err.(types.ErrorDoesNotExist); ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set(common.CONTENT_TYPE_HEADER, common.CONTENT_TYPE_JSON)
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(workspace); err != nil {
		logrus.Errorf("failed to send the workspace json in the response. Error: %q", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if common.Config.AuthEnabled && common.Config.CloudEventsEnabled {
		logrus.Debug("HandleReadWorkspace CloudEvents start")
		session, err := sessions.GetSession(r)
		if err != nil {
			logrus.Debugf("failed to get the session. Error: %q", err)
			return
		}
		email := ""
		if session.User.Email != nil {
			email = *session.User.Email
		}
		if err := cloudevents.SendCloudEvent(
			r.URL.Path,
			map[string]interface{}{
				cloudevents.CLOUD_EVENT_USER_EMAIL: email,
				cloudevents.CLOUD_EVENT_TEAM_NAME:  workspace.Name,
			},
		); err != nil {
			logrus.Debugf("failed to send the cloud event. Error: %q", err)
		}
		logrus.Debug("HandleReadWorkspace CloudEvents end")
	}
}

// HandleUpdateWorkspace handles updating an existing workspace
func HandleUpdateWorkspace(w http.ResponseWriter, r *http.Request) {
	logrus := GetLogger(r)
	logrus.Trace("HandleUpdateWorkspace start")
	defer logrus.Trace("HandleUpdateWorkspace end")
	routeVars := mux.Vars(r)
	workspaceId := routeVars[WORKSPACE_ID_ROUTE_VAR]
	if !common.IsValidId(workspaceId) {
		logrus.Errorf("the workspace id is invalid. Actual: %s", workspaceId)
		sendErrorJSON(w, "invalid workspace id", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()
	reqWorkspace := types.Workspace{}
	if err := json.NewDecoder(r.Body).Decode(&reqWorkspace); err != nil {
		logrus.Errorf("failed to parse the request body as json to Workspace. Error: %q", err)
		sendErrorJSON(w, "failed to parse the request body as a workspace json", http.StatusBadRequest)
		return
	}
	if reqWorkspace.Id != "" && reqWorkspace.Id != workspaceId {
		logrus.Errorf("the workspace id does not match the url. Request url id: %s Request body workspace id: %s", workspaceId, reqWorkspace.Id)
		sendErrorJSON(w, "the workspace id in the request body does not match the id in the URL", http.StatusBadRequest)
		return
	}
	reqWorkspace.Id = workspaceId
	oldWork, err := m2kFS.ReadWorkspace(workspaceId)
	if err != nil {
		if _, ok := err.(types.ErrorDoesNotExist); ok {
			logrus.Infof("the workspace with id: %s does not exist. creating...", workspaceId)
			timestamp, _, err := common.GetTimestamp()
			if err != nil {
				logrus.Errorf("failed to get the timestamp. Error: %q", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			reqWorkspace.Timestamp = timestamp
			reqWorkspace.ProjectIds = []string{}
			if err := m2kFS.CreateWorkspace(reqWorkspace); err != nil {
				if _, ok := err.(types.ErrorValidation); ok {
					sendErrorJSON(w, "the project given in the request body is invalid", http.StatusBadRequest)
					return
				}
				logrus.Errorf("failed to create the workspace. Error: %q", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusCreated)
			return
		}
		logrus.Errorf("failed to get the workspace with id: %s Error: %q", workspaceId, err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	reqWorkspace.ProjectIds = oldWork.ProjectIds
	if err := m2kFS.UpdateWorkspace(reqWorkspace); err != nil {
		logrus.Errorf("failed to update the workspace. Error: %q", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// HandleDeleteWorkspace handles deleting an existing workspace
func HandleDeleteWorkspace(w http.ResponseWriter, r *http.Request) {
	logrus := GetLogger(r)
	logrus.Trace("HandleDeleteWorkspace start")
	defer logrus.Trace("HandleDeleteWorkspace end")
	routeVars := mux.Vars(r)
	workspaceId := routeVars[WORKSPACE_ID_ROUTE_VAR]
	if !common.IsValidId(workspaceId) {
		logrus.Errorf("the workspace id is invalid. Actual: %s", workspaceId)
		sendErrorJSON(w, "invalid workspace id", http.StatusBadRequest)
		return
	}
	if err := m2kFS.DeleteWorkspace(workspaceId); err != nil {
		if _, ok := err.(types.ErrorDoesNotExist); ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if e, ok := err.(types.ErrorOngoing); ok {
			sendErrorJSON(w, fmt.Sprintf("cannot delete a workspace while one of its projects' planning/transformation is ongoing. Ongoing for id: %s", e.Id), http.StatusConflict)
			return
		}
		logrus.Errorf("failed to remove the workspace id: %s . Error: %q", workspaceId, err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
