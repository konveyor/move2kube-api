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
	"encoding/json"
	"io/ioutil"
	"net/http"
	"path"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/konveyor/move2kube-api/internal/common"
	"github.com/konveyor/move2kube-api/internal/types"
	"github.com/sirupsen/logrus"
)

// HandleListRoles handles listing all the roles
func HandleListRoles(w http.ResponseWriter, r *http.Request) {
	logrus.Trace("HandleListRoles start")
	accessToken, err := common.GetAccesTokenFromAuthzHeader(r)
	if err != nil {
		logrus.Debugf("failed to get the access token from the request. Error: %q", err)
		w.Header().Set(common.AUTHENTICATE_HEADER, common.AUTHENTICATE_HEADER_MSG)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	roleInfos, err := common.AuthServerClient.GetClientRoles(context.TODO(), accessToken, common.Config.AuthServerRealm, common.Config.M2kClientIdNotClientId)
	if err != nil {
		logrus.Debug("Error:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	// workaround to get role attributes. See https://github.com/Nerzal/gocloak/issues/216
	for _, roleInfo := range roleInfos {
		tr, err := common.AuthServerClient.GetClientRole(context.TODO(), accessToken, common.Config.AuthServerRealm, common.Config.M2kClientIdNotClientId, *roleInfo.Name)
		if err != nil {
			logrus.Debug("Error:", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if tr.Attributes != nil {
			roleInfo.Attributes = tr.Attributes
		}
	}

	m2kRoleInfos := []types.Role{}
	for _, roleInfo := range roleInfos {
		m2kRoleInfos = append(m2kRoleInfos, types.FromAuthServerRole(*roleInfo))
	}
	m2kRoleInfosBytes, err := json.Marshal(m2kRoleInfos)
	if err != nil {
		logrus.Debug("Error:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set(common.CONTENT_TYPE_HEADER, common.CONTENT_TYPE_JSON)
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(m2kRoleInfosBytes); err != nil {
		logrus.Debug("Error:", err)
	}
	logrus.Trace("HandleListRoles end")
}

// HandleCreateRole handles creating a new role
func HandleCreateRole(w http.ResponseWriter, r *http.Request) {
	logrus.Trace("HandleCreateRole start")
	accessToken, err := common.GetAccesTokenFromAuthzHeader(r)
	if err != nil {
		logrus.Debugf("failed to get the access token from the request. Error: %q", err)
		w.Header().Set(common.AUTHENTICATE_HEADER, common.AUTHENTICATE_HEADER_MSG)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	defer r.Body.Close()
	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		logrus.Debugf("failed to read the request body. Error: %q", err)
		sendErrorJSON(w, "the request body is missing or incomplete", http.StatusBadRequest)
		return
	}
	reqRole := types.Role{}
	if err := json.Unmarshal(bodyBytes, &reqRole); err != nil {
		logrus.Debug("failed to unmarshal the request body as json. Error:", err)
		sendErrorJSON(w, "the request body is invalid.", http.StatusBadRequest)
		return
	}
	logrus.Debug("trying to create the role:", reqRole)
	timestamp, _, err := common.GetTimestamp()
	if err != nil {
		logrus.Errorf("failed to get the timestamp. Error: %q", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	reqRole.Id = uuid.New().String()
	reqRole.Timestamp = timestamp
	logrus.Debug("after generating a new id for the role:", reqRole)
	authServerRole, err := reqRole.ToAuthServerRole()
	if err != nil {
		logrus.Errorf("failed to convert the request role into an authorization server role. Error: %q", err)
		sendErrorJSON(w, "the role is invalid", http.StatusBadRequest)
		return
	}
	logrus.Debug("after converting to auth server role:", authServerRole)
	if _, err := common.AuthServerClient.CreateClientRole(context.TODO(), accessToken, common.Config.AuthServerRealm, common.Config.M2kClientIdNotClientId, authServerRole); err != nil {
		logrus.Debug("failed to create the role at the authorization server. Error:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	result := map[string]string{"id": reqRole.Id}
	resultBytes, err := json.Marshal(result)
	if err != nil {
		logrus.Debug("Error:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Location", path.Clean(r.URL.Path+"/"+reqRole.Id))
	w.Header().Set(common.CONTENT_TYPE_HEADER, common.CONTENT_TYPE_JSON)
	w.WriteHeader(http.StatusCreated)
	if _, err := w.Write(resultBytes); err != nil {
		logrus.Errorf("failed to write the response body. Error: %q", err)
	}
	logrus.Trace("HandleCreateRole end")
}

// HandleReadRole handles reading an existing role
func HandleReadRole(w http.ResponseWriter, r *http.Request) {
	logrus.Trace("HandleReadRole start")
	accessToken, err := common.GetAccesTokenFromAuthzHeader(r)
	if err != nil {
		logrus.Debugf("failed to get the access token from the request. Error: %q", err)
		w.Header().Set(common.AUTHENTICATE_HEADER, common.AUTHENTICATE_HEADER_MSG)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	roleId := mux.Vars(r)[ROLE_ID_ROUTE_VAR]
	roleInfo, err := common.AuthServerClient.GetClientRole(context.TODO(), accessToken, common.Config.AuthServerRealm, common.Config.M2kClientIdNotClientId, roleId)
	if err != nil {
		logrus.Debugf("failed to get information about the role with id %s from the authorization server. Error: %q\n", roleId, err)
		w.WriteHeader(http.StatusNotFound)
		return
	}
	m2kRoleInfo := types.FromAuthServerRole(*roleInfo)
	m2kRoleInfoBytes, err := json.Marshal(m2kRoleInfo)
	if err != nil {
		logrus.Debug("Error:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set(common.CONTENT_TYPE_HEADER, common.CONTENT_TYPE_JSON)
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(m2kRoleInfoBytes); err != nil {
		logrus.Errorf("failed to write the response body. Error: %q", err)
	}
	logrus.Trace("HandleReadRole end")
}

// HandleUpdateRole handles updating an existing role
func HandleUpdateRole(w http.ResponseWriter, r *http.Request) {
	logrus.Trace("HandleUpdateRole start")
	accessToken, err := common.GetAccesTokenFromAuthzHeader(r)
	if err != nil {
		logrus.Debugf("failed to get the access token from the request. Error: %q", err)
		w.Header().Set(common.AUTHENTICATE_HEADER, common.AUTHENTICATE_HEADER_MSG)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	defer r.Body.Close()
	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		logrus.Debugf("failed to read the request body. Error: %q", err)
		sendErrorJSON(w, "the request body is missing or incomplete", http.StatusBadRequest)
		return
	}
	reqRole := types.Role{}
	if err := json.Unmarshal(bodyBytes, &reqRole); err != nil {
		logrus.Debugf("failed to unmarshal the request body as json. Error: %q", err)
		sendErrorJSON(w, "the request body is invalid.", http.StatusBadRequest)
		return
	}
	roleId := mux.Vars(r)[ROLE_ID_ROUTE_VAR]
	if reqRole.Id != "" && reqRole.Id != roleId {
		logrus.Debugf("the role in the request body json does not match the role id in the URL. Expected: %s Actual: %+v\n", roleId, reqRole)
		sendErrorJSON(w, "the role id in the url does not match the role id in the request body", http.StatusBadRequest)
		return
	}
	reqRole.Id = roleId
	logrus.Debug("trying to update the role:", reqRole)
	authServerRole, err := reqRole.ToAuthServerRole()
	if err != nil {
		logrus.Errorf("failed to convert the request role into an authorization server role. Error: %q", err)
		sendErrorJSON(w, "the role is invalid", http.StatusBadRequest)
		return
	}
	newRole := false
	if _, err := common.AuthServerClient.GetClientRole(context.TODO(), accessToken, common.Config.AuthServerRealm, common.Config.M2kClientIdNotClientId, roleId); err != nil {
		logrus.Debugf("failed to get information about the role with id %s from the authorization server. Error: %q\n", roleId, err)
		logrus.Debug("creating a new role instead of updating an existing role.")
		newRole = true
	}
	if newRole {
		timestamp, _, err := common.GetTimestamp()
		if err != nil {
			logrus.Errorf("failed to get the timestamp. Error: %q", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		reqRole.Timestamp = timestamp
		if _, err := common.AuthServerClient.CreateClientRole(context.TODO(), accessToken, common.Config.AuthServerRealm, common.Config.M2kClientIdNotClientId, authServerRole); err != nil {
			logrus.Debug("failed to create the role at the authorization server. Error:", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Location", r.URL.Path)
		w.WriteHeader(http.StatusCreated)
		return
	}
	if err := common.AuthServerClient.UpdateRole(context.TODO(), accessToken, common.Config.AuthServerRealm, common.Config.M2kClientIdNotClientId, authServerRole); err != nil {
		logrus.Debugf("failed to update the role with id %s from the authorization server. Error: %q\n", roleId, err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
	logrus.Trace("HandleUpdateRole end")
}

// HandleDeleteRole handles deleting an existing role
func HandleDeleteRole(w http.ResponseWriter, r *http.Request) {
	logrus.Trace("HandleDeleteRole start")
	accessToken, err := common.GetAccesTokenFromAuthzHeader(r)
	if err != nil {
		logrus.Debugf("failed to get the access token from the request. Error: %q", err)
		w.Header().Set(common.AUTHENTICATE_HEADER, common.AUTHENTICATE_HEADER_MSG)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	roleId := mux.Vars(r)[ROLE_ID_ROUTE_VAR]
	if err := common.AuthServerClient.DeleteClientRole(context.TODO(), accessToken, common.Config.AuthServerRealm, common.Config.M2kClientIdNotClientId, roleId); err != nil {
		logrus.Debugf("failed to delete the role with id %s and name %s from the authorization server. Error: %q\n", roleId, roleId, err)
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
	logrus.Trace("HandleDeleteRole end")
}
