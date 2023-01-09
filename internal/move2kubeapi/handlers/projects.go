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
	"github.com/konveyor/move2kube-api/internal/common"
	"github.com/konveyor/move2kube-api/internal/types"
)

// HandleListProjects handles listing projects
func HandleListProjects(w http.ResponseWriter, r *http.Request) {
	logrus := GetLogger(r)
	logrus.Trace("HandleListProjects start")
	defer logrus.Trace("HandleListProjects end")
	routeVars := mux.Vars(r)
	workspaceId := routeVars[WORKSPACE_ID_ROUTE_VAR]
	if !common.IsValidId(workspaceId) {
		logrus.Errorf("invalid workspace id. Actual: %s", workspaceId)
		sendErrorJSON(w, "invalid workspace id", http.StatusBadRequest)
		return
	}
	projects, err := m2kFS.ListProjects(workspaceId)
	if err != nil {
		logrus.Errorf("failed to list the projects. Error: %q", err)
		if _, ok := err.(types.ErrorDoesNotExist); ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set(common.CONTENT_TYPE_HEADER, common.CONTENT_TYPE_JSON)
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(projects); err != nil {
		logrus.Errorf("failed to send the json response to the client. Error: %q", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

// HandleCreateProject handles creating a new project
func HandleCreateProject(w http.ResponseWriter, r *http.Request) {
	logrus := GetLogger(r)
	logrus.Trace("HandleCreateProject start")
	defer logrus.Trace("HandleCreateProject end")
	routeVars := mux.Vars(r)
	workspaceId := routeVars[WORKSPACE_ID_ROUTE_VAR]
	if !common.IsValidId(workspaceId) {
		logrus.Errorf("invalid workspace id. Actual: %s", workspaceId)
		sendErrorJSON(w, "invalid workspace id", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()
	newProject := types.Project{}
	if err := json.NewDecoder(r.Body).Decode(&newProject); err != nil {
		logrus.Errorf("failed to unmarshal the request body as a project. Error: %q", err)
		sendErrorJSON(w, "failed to unmarshal the request body as a project", http.StatusBadRequest)
		return
	}
	timestamp, _, err := common.GetTimestamp()
	if err != nil {
		logrus.Errorf("failed to get the timestamp. Error: %q", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	newProject.Id = uuid.NewString()
	newProject.Timestamp = timestamp
	newProject.Inputs = map[string]types.ProjectInput{}
	newProject.Outputs = map[string]types.ProjectOutput{}
	newProject.Status = map[types.ProjectStatus]bool{}
	if err := m2kFS.CreateProject(workspaceId, newProject); err != nil {
		logrus.Errorf("failed to create the project. Error: %q", err)
		if _, ok := err.(types.ErrorDoesNotExist); ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if _, ok := err.(types.ErrorValidation); ok {
			sendErrorJSON(w, "the project given in the request body is invalid", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(map[string]string{"id": newProject.Id}); err != nil {
		logrus.Errorf("failed to write the response to client. Error: %q", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

// HandleUpdateProject handles updating an existing project
func HandleUpdateProject(w http.ResponseWriter, r *http.Request) {
	logrus := GetLogger(r)
	logrus.Trace("HandleUpdateProject start")
	defer logrus.Trace("HandleUpdateProject end")
	routeVars := mux.Vars(r)
	workspaceId := routeVars[WORKSPACE_ID_ROUTE_VAR]
	if !common.IsValidId(workspaceId) {
		logrus.Errorf("the workspace id is invalid. Actual: %s", workspaceId)
		sendErrorJSON(w, "invalid workspace id", http.StatusBadRequest)
		return
	}
	projectId := routeVars[PROJECT_ID_ROUTE_VAR]
	if !common.IsValidId(projectId) {
		logrus.Errorf("the project id is invalid. Actual: %s", projectId)
		sendErrorJSON(w, "invalid project id", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()
	reqProject := types.Project{}
	if err := json.NewDecoder(r.Body).Decode(&reqProject); err != nil {
		logrus.Errorf("failed to parse the request body as json to Project. Error: %q", err)
		sendErrorJSON(w, "failed to parse the request body as a project json", http.StatusBadRequest)
		return
	}
	if reqProject.Id != "" && reqProject.Id != projectId {
		logrus.Errorf("the project id does not match the url. Request url id: %s Request body project id: %s", projectId, reqProject.Id)
		sendErrorJSON(w, "the project id in the request body does not match the id in the URL", http.StatusBadRequest)
		return
	}
	reqProject.Id = projectId
	oldProj, err := m2kFS.ReadProject(workspaceId, projectId)
	if err != nil {
		if _, ok := err.(types.ErrorDoesNotExist); !ok {
			logrus.Errorf("failed to get the project with id: %s in the workspace with id: %s Error: %q", projectId, workspaceId, err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		logrus.Infof("the project with id: %s does not exist in the workspace with id: %s . creating...", projectId, workspaceId)
		timestamp, _, err := common.GetTimestamp()
		if err != nil {
			logrus.Errorf("failed to get the timestamp. Error: %q", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		reqProject.Timestamp = timestamp
		reqProject.Inputs = map[string]types.ProjectInput{}
		reqProject.Outputs = map[string]types.ProjectOutput{}
		reqProject.Status = map[types.ProjectStatus]bool{}
		if err := m2kFS.CreateProject(workspaceId, reqProject); err != nil {
			logrus.Errorf("failed to create the project. Error: %q", err)
			if _, ok := err.(types.ErrorValidation); ok {
				sendErrorJSON(w, "the project given in the request body is invalid", http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
		return
	}
	reqProject.Timestamp = oldProj.Timestamp
	reqProject.Inputs = oldProj.Inputs
	reqProject.Outputs = oldProj.Outputs
	reqProject.Status = oldProj.Status
	if err := m2kFS.UpdateProject(workspaceId, reqProject); err != nil {
		logrus.Errorf("failed to update the project. Error: %q", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// HandleReadProject handles reading an existing project
func HandleReadProject(w http.ResponseWriter, r *http.Request) {
	logrus := GetLogger(r)
	logrus.Trace("HandleReadProject start")
	defer logrus.Trace("HandleReadProject end")
	routeVars := mux.Vars(r)
	workspaceId := routeVars[WORKSPACE_ID_ROUTE_VAR]
	if !common.IsValidId(workspaceId) {
		logrus.Errorf("invalid workspace id. Actual: %s", workspaceId)
		sendErrorJSON(w, "invalid workspace id", http.StatusBadRequest)
		return
	}
	projectId := mux.Vars(r)[PROJECT_ID_ROUTE_VAR]
	logrus.Debugf("reading project with id: %s", projectId)
	project, err := m2kFS.ReadProject(workspaceId, projectId)
	if err != nil {
		logrus.Errorf("failed to read the project with id %s . Error: %q", projectId, err)
		if _, ok := err.(types.ErrorDoesNotExist); ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(project); err != nil {
		logrus.Errorf("failed to send the response json to the client. Error: %q", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

// HandleDeleteProject handles deleting an existing project
func HandleDeleteProject(w http.ResponseWriter, r *http.Request) {
	logrus := GetLogger(r)
	logrus.Trace("HandleDeleteProject start")
	defer logrus.Trace("HandleDeleteProject end")
	routeVars := mux.Vars(r)
	workspaceId := routeVars[WORKSPACE_ID_ROUTE_VAR]
	if !common.IsValidId(workspaceId) {
		logrus.Errorf("invalid workspace id. Actual: %s", workspaceId)
		sendErrorJSON(w, "invalid workspace id", http.StatusBadRequest)
		return
	}
	projectId := mux.Vars(r)[PROJECT_ID_ROUTE_VAR]
	if err := m2kFS.DeleteProject(workspaceId, projectId); err != nil {
		logrus.Errorf("failed to delete the project with id %s . Error: %q", projectId, err)
		if _, ok := err.(types.ErrorDoesNotExist); ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if e, ok := err.(types.ErrorValidation); ok {
			sendErrorJSON(w, e.Reason, http.StatusBadRequest)
			return
		}
		if e, ok := err.(types.ErrorOngoing); ok {
			sendErrorJSON(w, fmt.Sprintf("cannot delete a project while its planning/transformation is ongoing. Ongoing for id: %s", e.Id), http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	logrus.Infof("project with id %s has been deleted successfully", projectId)
}
