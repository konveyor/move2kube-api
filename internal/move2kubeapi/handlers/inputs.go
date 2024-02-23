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
	"mime/multipart"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/konveyor/move2kube-api/internal/common"
	"github.com/konveyor/move2kube-api/internal/types"
)

// HandleCreateProjectInput is the handler for creating a project input
// isCommon: if true the input will be available for all the projects in the workspace
func HandleCreateProjectInput(w http.ResponseWriter, r *http.Request, isCommon bool) {
	logrus := GetLogger(r)
	logrus.Trace("HandleCreateProjectInput start")
	defer logrus.Trace("HandleCreateProjectInput end")
	workspaceId := mux.Vars(r)[WORKSPACE_ID_ROUTE_VAR]
	if !common.IsValidId(workspaceId) {
		logrus.Errorf("invalid workspace id. Actual: %s", workspaceId)
		sendErrorJSON(w, "invalid workspace id", http.StatusBadRequest)
		return
	}
	projectId := ""
	if !isCommon {
		projectId = mux.Vars(r)[PROJECT_ID_ROUTE_VAR]
		if !common.IsValidId(projectId) {
			logrus.Errorf("invalid project id. Actual: %s", projectId)
			sendErrorJSON(w, "invalid project id", http.StatusBadRequest)
			return
		}
	}
	r.Body = http.MaxBytesReader(w, r.Body, common.Config.MaxUploadSize)
	if err := r.ParseMultipartForm(common.Config.MaxUploadSize); err != nil {
		if _, ok := err.(*http.MaxBytesError); ok {
			logrus.Errorf("request body exceeded max upload size of '%d' bytes. Error: %q", common.Config.MaxUploadSize, err)
			sendErrorJSON(
				w,
				"Request body exceeded max upload size. Try using a smaller input or contact your Admin to increase the max upload size.",
				http.StatusBadRequest,
			)
			return
		}
		logrus.Errorf("failed to parse the request body as multipart/form-data. Error: %q", err)
		sendErrorJSON(w, "failed to parse the request body as multipart/form-data", http.StatusBadRequest)
		return
	}
	timestamp, _, err := common.GetTimestamp()
	if err != nil {
		logrus.Errorf("failed to get the timestamp. Error: %q", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	projType, err := types.ParseProjectInputType(r.FormValue("type"))
	if err != nil {
		logrus.Errorf("failed to parse the project input type. Error: %q", err)
		sendErrorJSON(w, "the input type is invalid", http.StatusBadRequest)
		return
	}
	var file io.ReadCloser
	filename := ""
	normName := ""
	projInputId := uuid.NewString()
	if projType == types.ProjectInputReference {
		if isCommon {
			logrus.Errorf("cannot upload reference type input for workspaces")
			sendErrorJSON(w, "cannot upload reference type input for workspaces", http.StatusBadRequest)
			return
		}
		projInputId = r.FormValue("id")
		if !common.IsValidId(projInputId) {
			logrus.Errorf("the reference input id is invalid. Actual: %s", projInputId)
			sendErrorJSON(w, "the reference input id is invalid", http.StatusBadRequest)
			return
		}
	} else {
		var fileHeader *multipart.FileHeader
		file, fileHeader, err = r.FormFile("file")
		if err != nil {
			logrus.Errorf("failed to get the file from the request body. Error: %q", err)
			sendErrorJSON(w, "failed to get the file from the request body", http.StatusBadRequest)
			return
		}
		filename = fileHeader.Filename
		defer file.Close()
		normName = filepath.Base(filepath.Clean(filename))
		normName = strings.TrimSuffix(normName, filepath.Ext(normName))
		normName, err = common.NormalizeName(normName)
		if err != nil {
			logrus.Errorf("failed to normalize the filename '%s'. Error: %q", filename, err)
			sendErrorJSON(w, "failed to normalize the filename. Please use a filename that has only alphanumeric and hyphen characters.", http.StatusBadRequest)
			return
		}
	}
	projInput := types.ProjectInput{Metadata: types.Metadata{Id: projInputId, Name: filename, Description: r.FormValue("description"), Timestamp: timestamp}, Type: projType, NormalizedName: normName}
	logrus.Debug("trying to create a new input for the project", projectId, " with the details:", projInput)
	if err := m2kFS.CreateProjectInput(workspaceId, projectId, projInput, file, isCommon); err != nil {
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
}

// HandleReadProjectInput is the handler for reading a project input
func HandleReadProjectInput(w http.ResponseWriter, r *http.Request, isCommon bool) {
	logrus := GetLogger(r)
	logrus.Trace("HandleReadProjectInput start")
	defer logrus.Trace("HandleReadProjectInput end")
	workspaceId := mux.Vars(r)[WORKSPACE_ID_ROUTE_VAR]
	projectId := mux.Vars(r)[PROJECT_ID_ROUTE_VAR]
	projInputId := mux.Vars(r)[PROJECT_INPUT_ID_ROUTE_VAR]
	if !common.IsValidId(workspaceId) || !common.IsValidId(projInputId) {
		logrus.Errorf("invalid workspace and/or project input id. Actual: %s %s", workspaceId, projInputId)
		sendErrorJSON(w, "invalid workspace and/or project input id", http.StatusBadRequest)
		return
	}
	if !isCommon {
		if !common.IsValidId(projectId) {
			logrus.Errorf("invalid project id. Actual: %s", projectId)
			sendErrorJSON(w, "invalid project id", http.StatusBadRequest)
			return
		}
	}
	projInput, file, err := m2kFS.ReadProjectInput(workspaceId, projectId, projInputId, isCommon)
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
}

// HandleDeleteProjectInput is the handler for deleting a project input
func HandleDeleteProjectInput(w http.ResponseWriter, r *http.Request, isCommon bool) {
	logrus := GetLogger(r)
	logrus.Trace("HandleDeleteProjectInput start")
	defer logrus.Trace("HandleDeleteProjectInput end")
	workspaceId := mux.Vars(r)[WORKSPACE_ID_ROUTE_VAR]
	projectId := mux.Vars(r)[PROJECT_ID_ROUTE_VAR]
	projInputId := mux.Vars(r)[PROJECT_INPUT_ID_ROUTE_VAR]
	if !common.IsValidId(workspaceId) || !common.IsValidId(projInputId) {
		logrus.Errorf("invalid workspace and/or project input id. Actual: %s %s", workspaceId, projInputId)
		sendErrorJSON(w, "invalid workspace and/or project input id", http.StatusBadRequest)
		return
	}
	if !isCommon {
		if !common.IsValidId(projectId) {
			logrus.Errorf("invalid project id. Actual: %s", projectId)
			sendErrorJSON(w, "invalid project id", http.StatusBadRequest)
			return
		}
	}
	if err := m2kFS.DeleteProjectInput(workspaceId, projectId, projInputId, isCommon); err != nil {
		logrus.Errorf("failed to delete the input %s of the project %s . Error: %q", projInputId, projectId, err)
		if _, ok := err.(types.ErrorDoesNotExist); ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if _, ok := err.(types.ErrorOngoing); ok {
			// TODO: allow cancelling the planning
			sendErrorJSON(w, "cannot delete project inputs while planning is ongoing", http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
