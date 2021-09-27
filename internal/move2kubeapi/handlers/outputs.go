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
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/konveyor/move2kube-api/internal/common"
	"github.com/konveyor/move2kube-api/internal/types"
	"github.com/sirupsen/logrus"
)

// HandleStartTransformation handles starting a new transformation
func HandleStartTransformation(w http.ResponseWriter, r *http.Request) {
	logrus.Trace("HandleStartTransformation start")
	workspaceId := mux.Vars(r)[WORKSPACE_ID_ROUTE_VAR]
	projectId := mux.Vars(r)[PROJECT_ID_ROUTE_VAR]
	if !common.IsValidId(workspaceId) || !common.IsValidId(projectId) {
		logrus.Errorf("invalid id. Actual: %s %s", workspaceId, projectId)
		sendErrorJSON(w, "invalid id", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()
	reqBody := struct{ Plan string }{}
	var planReader io.Reader
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err == nil {
		planReader = bytes.NewBufferString(reqBody.Plan)
	} else {
		if err != io.EOF {
			sendErrorJSON(w, "invalid request body", http.StatusBadRequest)
			return
		}
		// empty body
		planReader = nil
	}
	debugMode := r.URL.Query().Get(DEBUG_QUERY_PARAM) == "true"
	timestamp, _, err := common.GetTimestamp()
	if err != nil {
		logrus.Errorf("failed to get the timestamp. Error: %q", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	projOutput := types.ProjectOutput{}
	projOutput.Id = uuid.NewString()
	projOutput.Timestamp = timestamp
	projOutput.Name = projOutput.Id // This isn't really used anywhere
	projOutput.Status = types.ProjectOutputStatusInProgress
	if err := m2kFS.StartTransformation(workspaceId, projectId, projOutput, planReader, debugMode); err != nil {
		logrus.Errorf("failed to start the transformation. Error: %q", err)
		if notExErr, ok := err.(types.ErrorDoesNotExist); ok {
			if notExErr.Id == "plan" {
				sendErrorJSON(w, "generate a plan before starting transformation", http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if _, ok := err.(types.ErrorOngoing); ok {
			w.WriteHeader(http.StatusForbidden)
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
	w.WriteHeader(http.StatusAccepted)
	if err := json.NewEncoder(w).Encode(projOutput); err != nil {
		logrus.Errorf("failed to send the response. Error: %q", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	logrus.Trace("HandleStartTransformation end")
}

// HandleReadProjectOutput handles reading the output of a transformation
func HandleReadProjectOutput(w http.ResponseWriter, r *http.Request) {
	logrus.Trace("HandleReadProjectOutput start")
	workspaceId := mux.Vars(r)[WORKSPACE_ID_ROUTE_VAR]
	projectId := mux.Vars(r)[PROJECT_ID_ROUTE_VAR]
	projOutputId := mux.Vars(r)[PROJECT_OUTPUT_ID_ROUTE_VAR]
	if !common.IsValidId(workspaceId) || !common.IsValidId(projectId) || !common.IsValidId(projOutputId) {
		logrus.Errorf("invalid id. Actual: %s %s %s", workspaceId, projectId, projOutputId)
		sendErrorJSON(w, "invalid id", http.StatusBadRequest)
		return
	}
	_, file, err := m2kFS.ReadProjectOutput(workspaceId, projectId, projOutputId)
	if err != nil {
		logrus.Errorf("failed to get the project output. Error: %q", err)
		if _, ok := err.(types.ErrorDoesNotExist); ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if _, ok := err.(types.ErrorOngoing); ok {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set(common.CONTENT_TYPE_HEADER, common.CONTENT_TYPE_BINARY)
	w.Header().Set("Content-Disposition", "attachment")
	w.WriteHeader(http.StatusOK)
	if _, err := io.Copy(w, file); err != nil {
		logrus.Errorf("failed to send the response. Error: %q", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	logrus.Trace("HandleReadProjectOutput end")
}

// HandleDeleteProjectOutput handles deleting the output of a transformation
func HandleDeleteProjectOutput(w http.ResponseWriter, r *http.Request) {
	logrus.Trace("HandleDeleteProjectOutput start")
	workspaceId := mux.Vars(r)[WORKSPACE_ID_ROUTE_VAR]
	projectId := mux.Vars(r)[PROJECT_ID_ROUTE_VAR]
	projOutputId := mux.Vars(r)[PROJECT_OUTPUT_ID_ROUTE_VAR]
	if !common.IsValidId(workspaceId) || !common.IsValidId(projectId) || !common.IsValidId(projOutputId) {
		logrus.Errorf("invalid id. Actual: %s %s %s", workspaceId, projectId, projOutputId)
		sendErrorJSON(w, "invalid id", http.StatusBadRequest)
		return
	}
	if err := m2kFS.DeleteProjectOutput(workspaceId, projectId, projOutputId); err != nil {
		logrus.Errorf("failed to delete the project output. Error: %q", err)
		if _, ok := err.(types.ErrorDoesNotExist); ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if _, ok := err.(types.ErrorOngoing); ok {
			// TODO: allow cancelling the transformation
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
	logrus.Trace("HandleDeleteProjectOutput end")
}
