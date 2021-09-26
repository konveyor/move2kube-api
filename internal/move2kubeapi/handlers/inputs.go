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
	"io"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/konveyor/move2kube-api/internal/common"
	"github.com/konveyor/move2kube-api/internal/types"
	"github.com/sirupsen/logrus"
)

// HandleCreateProjectInput is the handler for creating a project input
func HandleCreateProjectInput(w http.ResponseWriter, r *http.Request) {
	logrus.Trace("HandleCreateProjectInput start")
	workspaceId := mux.Vars(r)[WORKSPACE_ID_ROUTE_VAR]
	projectId := mux.Vars(r)[PROJECT_ID_ROUTE_VAR]
	if !common.IsValidId(workspaceId) || !common.IsValidId(projectId) {
		logrus.Error("invalid id. Actual:", projectId)
		sendErrorJSON(w, "invalid id", http.StatusBadRequest)
		return
	}
	file, handler, err := r.FormFile("file")
	if err != nil {
		logrus.Errorf("failed to get the file from the request body. Error: %q", err)
		sendErrorJSON(w, "failed to get the file from the request body.", http.StatusBadRequest)
		return
	}
	defer file.Close()
	projType, err := types.ParseProjectInputType(r.FormValue("type"))
	if err != nil {
		logrus.Errorf("failed to parse the project input type. Error: %q", err)
		sendErrorJSON(w, "the input type is invalid", http.StatusBadRequest)
		return
	}
	timestamp, _, err := common.GetTimestamp()
	if err != nil {
		logrus.Errorf("failed to get the timestamp. Error: %q", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	normName := filepath.Base(filepath.Clean(handler.Filename))
	normName = strings.TrimSuffix(normName, filepath.Ext(normName))
	normName, err = common.NormalizeName(normName)
	if err != nil {
		logrus.Errorf("failed to normalize the filename '%s'. Error: %q", handler.Filename, err)
		sendErrorJSON(w, "failed to normalize the filename. Please use a filename that has only alphanumeric and hyphen characters.", http.StatusBadRequest)
		return
	}
	projInput := types.ProjectInput{Metadata: types.Metadata{Id: uuid.NewString(), Name: handler.Filename, Description: r.FormValue("description"), Timestamp: timestamp}, Type: projType, NormalizedName: normName}
	logrus.Debug("trying to create a new input for the project", projectId, " with the details:", projInput)
	if err := m2kFS.CreateProjectInput(workspaceId, projectId, projInput, file); err != nil {
		logrus.Errorf("failed to create the project input. Error: %q", err)
		if _, ok := err.(types.ErrorDoesNotExist); ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if e, ok := err.(types.ErrorValidation); ok {
			sendErrorJSON(w, e.Reason, http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set(common.CONTENT_TYPE_HEADER, common.CONTENT_TYPE_JSON)
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(map[string]string{"id": projInput.Id}); err != nil {
		logrus.Errorf("failed to write the response. Error: %q", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	logrus.Trace("HandleCreateProjectInput end")
}

// HandleReadProjectInput is the handler for reading a project input
func HandleReadProjectInput(w http.ResponseWriter, r *http.Request) {
	logrus.Trace("HandleReadProjectInput start")
	workspaceId := mux.Vars(r)[WORKSPACE_ID_ROUTE_VAR]
	projectId := mux.Vars(r)[PROJECT_ID_ROUTE_VAR]
	projInputId := mux.Vars(r)[PROJECT_INPUT_ID_ROUTE_VAR]
	if !common.IsValidId(workspaceId) || !common.IsValidId(projectId) || !common.IsValidId(projInputId) {
		logrus.Error("invalid id. Actual:", projectId)
		sendErrorJSON(w, "invalid id", http.StatusBadRequest)
		return
	}
	projInput, file, err := m2kFS.ReadProjectInput(workspaceId, projectId, projInputId)
	if err != nil {
		logrus.Errorf("failed to get the input with id %s for the project %s . Error: %q", projInputId, projectId, err)
		if _, ok := err.(types.ErrorDoesNotExist); ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set(common.CONTENT_TYPE_HEADER, common.CONTENT_TYPE_BINARY)
	w.Header().Set("Content-Disposition", "attachment; filename="+projInput.Name)
	w.WriteHeader(http.StatusOK)
	if _, err := io.Copy(w, file); err != nil {
		logrus.Errorf("failed to send the response. Error: %q", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	logrus.Trace("HandleReadProjectInput end")
}

// HandleDeleteProjectInput is the handler for deleting a project input
func HandleDeleteProjectInput(w http.ResponseWriter, r *http.Request) {
	logrus.Trace("HandleDeleteProjectInput start")
	workspaceId := mux.Vars(r)[WORKSPACE_ID_ROUTE_VAR]
	projectId := mux.Vars(r)[PROJECT_ID_ROUTE_VAR]
	projInputId := mux.Vars(r)[PROJECT_INPUT_ID_ROUTE_VAR]
	if !common.IsValidId(workspaceId) || !common.IsValidId(projectId) || !common.IsValidId(projInputId) {
		logrus.Error("invalid id. Actual:", projectId)
		sendErrorJSON(w, "invalid id", http.StatusBadRequest)
		return
	}
	if err := m2kFS.DeleteProjectInput(workspaceId, projectId, projInputId); err != nil {
		logrus.Errorf("failed to delete the input %s of the project %s . Error: %q", projInputId, projectId, err)
		if _, ok := err.(types.ErrorDoesNotExist); ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
	logrus.Trace("HandleDeleteProjectInput end")
}
