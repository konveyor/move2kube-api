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
	"io/ioutil"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/konveyor/move2kube-api/internal/common"
	"github.com/konveyor/move2kube-api/internal/types"
	"github.com/sirupsen/logrus"
)

// HandleStartPlanning handles starting the planning for a project
func HandleStartPlanning(w http.ResponseWriter, r *http.Request) {
	logrus.Trace("HandleStartPlanning start")
	workspaceId := mux.Vars(r)[WORKSPACE_ID_ROUTE_VAR]
	projectId := mux.Vars(r)[PROJECT_ID_ROUTE_VAR]
	if !common.IsValidId(workspaceId) || !common.IsValidId(projectId) {
		logrus.Error("invalid id. Actual:", projectId)
		sendErrorJSON(w, "invalid id", http.StatusBadRequest)
		return
	}
	debugMode := r.URL.Query().Get(DEBUG_QUERY_PARAM) == "true"
	if err := m2kFS.StartPlanning(workspaceId, projectId, debugMode); err != nil {
		logrus.Errorf("failed to start plan generation. Error: %q", err)
		if _, ok := err.(types.ErrorDoesNotExist); ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if e, ok := err.(types.ErrorValidation); ok {
			sendErrorJSON(w, e.Reason, http.StatusBadRequest)
			return
		}
		if _, ok := err.(types.ErrorOngoing); ok {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusAccepted)
	logrus.Trace("HandleStartPlanning end")
}

// HandleReadPlan handles reading the plan for a project
func HandleReadPlan(w http.ResponseWriter, r *http.Request) {
	logrus.Trace("HandleReadPlan start")
	workspaceId := mux.Vars(r)[WORKSPACE_ID_ROUTE_VAR]
	projectId := mux.Vars(r)[PROJECT_ID_ROUTE_VAR]
	if !common.IsValidId(workspaceId) || !common.IsValidId(projectId) {
		logrus.Error("invalid id. Actual:", projectId)
		sendErrorJSON(w, "invalid id", http.StatusBadRequest)
		return
	}
	plan, err := m2kFS.ReadPlan(workspaceId, projectId)
	if err != nil {
		logrus.Debugf("failed to get the plan. Error: %q", err)
		if _, ok := err.(types.ErrorDoesNotExist); ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if _, ok := err.(types.ErrorOngoing); ok {
			if plan != nil {
				planBytes, ok := plan.(*bytes.Buffer)
				if !ok {
					logrus.Errorf("the plan progress is not a *bytes.Buffer. Actual value is %+v of type %T", plan, plan)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				w.Header().Set(common.CONTENT_TYPE_HEADER, common.CONTENT_TYPE_JSON)
				w.WriteHeader(http.StatusAccepted)
				w.Write(planBytes.Bytes())
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	planBytes, err := ioutil.ReadAll(plan)
	if err != nil {
		logrus.Errorf("failed to read the plan file. Error: %q", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set(common.CONTENT_TYPE_HEADER, common.CONTENT_TYPE_JSON)
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]string{"plan": string(planBytes)}); err != nil {
		logrus.Errorf("failed to send the response. Error: %q", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	logrus.Trace("HandleReadPlan end")
}

// HandleUpdatePlan handles updating the plan for a project
func HandleUpdatePlan(w http.ResponseWriter, r *http.Request) {
	logrus.Trace("HandleUpdatePlan start")
	workspaceId := mux.Vars(r)[WORKSPACE_ID_ROUTE_VAR]
	projectId := mux.Vars(r)[PROJECT_ID_ROUTE_VAR]
	if !common.IsValidId(workspaceId) || !common.IsValidId(projectId) {
		logrus.Error("invalid id. Actual:", projectId)
		sendErrorJSON(w, "invalid id", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()
	reqBody := struct{ Plan string }{}
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		logrus.Errorf("failed to decode the request body as json. Error: %q", err)
		sendErrorJSON(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if err := m2kFS.UpdatePlan(workspaceId, projectId, bytes.NewBufferString(reqBody.Plan)); err != nil {
		logrus.Errorf("failed to update the plan. Error: %q", err)
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
	w.WriteHeader(http.StatusNoContent)
	logrus.Trace("HandleUpdatePlan end")
}

// HandleDeletePlan handles deleting the plan for a project
func HandleDeletePlan(w http.ResponseWriter, r *http.Request) {
	logrus.Trace("HandleDeletePlan start")
	workspaceId := mux.Vars(r)[WORKSPACE_ID_ROUTE_VAR]
	projectId := mux.Vars(r)[PROJECT_ID_ROUTE_VAR]
	if !common.IsValidId(workspaceId) || !common.IsValidId(projectId) {
		logrus.Error("invalid id. Actual:", projectId)
		sendErrorJSON(w, "invalid id", http.StatusBadRequest)
		return
	}
	if err := m2kFS.DeletePlan(workspaceId, projectId); err != nil {
		logrus.Errorf("failed to delete the plan. Error: %q", err)
		if _, ok := err.(types.ErrorDoesNotExist); ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
	logrus.Trace("HandleDeletePlan end")
}