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
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	logrus.Infof("project with id %s has been deleted successfully", projectId)
}
