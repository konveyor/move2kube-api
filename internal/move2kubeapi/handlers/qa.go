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

	"github.com/gorilla/mux"
	"github.com/konveyor/move2kube-api/internal/common"
	"github.com/konveyor/move2kube-api/internal/types"
)

// HandleGetQuestion handles getting the next question of an ongoing transformation
func HandleGetQuestion(w http.ResponseWriter, r *http.Request) {
	logrus := GetLogger(r)
	logrus.Trace("HandleGetQuestion start")
	defer logrus.Trace("HandleGetQuestion end")
	workspaceId := mux.Vars(r)[WORKSPACE_ID_ROUTE_VAR]
	projectId := mux.Vars(r)[PROJECT_ID_ROUTE_VAR]
	projOutputId := mux.Vars(r)[PROJECT_OUTPUT_ID_ROUTE_VAR]
	if !common.IsValidId(workspaceId) || !common.IsValidId(projectId) || !common.IsValidId(projOutputId) {
		logrus.Errorf("invalid id. Actual: %s %s %s", workspaceId, projectId, projOutputId)
		sendErrorJSON(w, "invalid id", http.StatusBadRequest)
		return
	}
	problem, err := m2kFS.GetQuestion(workspaceId, projectId, projOutputId)
	if err != nil {
		logrus.Errorf("failed to get the next question. Error: %q", err)
		if _, ok := err.(types.ErrorDoesNotExist); ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if problem == "" {
		logrus.Debugf("finished all the questions for output %s of project %s", projOutputId, projectId)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set(common.CONTENT_TYPE_HEADER, common.CONTENT_TYPE_JSON)
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]string{"question": problem}); err != nil {
		logrus.Errorf("failed to send the response. Error: %q", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

// HandlePostSolution handles posting the solution to the current question of an ongoing transformation
func HandlePostSolution(w http.ResponseWriter, r *http.Request) {
	logrus := GetLogger(r)
	logrus.Trace("HandlePostSolution start")
	defer logrus.Trace("HandlePostSolution end")
	workspaceId := mux.Vars(r)[WORKSPACE_ID_ROUTE_VAR]
	projectId := mux.Vars(r)[PROJECT_ID_ROUTE_VAR]
	projOutputId := mux.Vars(r)[PROJECT_OUTPUT_ID_ROUTE_VAR]
	if !common.IsValidId(workspaceId) || !common.IsValidId(projectId) || !common.IsValidId(projOutputId) {
		logrus.Errorf("invalid id. Actual: %s %s %s", workspaceId, projectId, projOutputId)
		sendErrorJSON(w, "invalid id", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()
	t1 := struct{ Solution string }{}
	if err := json.NewDecoder(r.Body).Decode(&t1); err != nil {
		logrus.Debugf("failed to unmarshal the request body as json. Error: %q", err)
		sendErrorJSON(w, "the request body is invalid", http.StatusBadRequest)
		return
	}
	if err := m2kFS.PostSolution(workspaceId, projectId, projOutputId, t1.Solution); err != nil {
		logrus.Errorf("failed to post the solution to the question. Error: %q", err)
		if _, ok := err.(types.ErrorDoesNotExist); ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if _, ok := err.(types.ErrorValidation); ok {
			sendErrorJSON(w, "the solution is invalid", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
