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
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/Nerzal/gocloak/v8"
	"github.com/gorilla/mux"
	"github.com/konveyor/move2kube-api/internal/common"
	"github.com/konveyor/move2kube-api/internal/types"
	"github.com/sirupsen/logrus"
)

// HandleListRoleBindings handles list all the roles of a particular user
func HandleListRoleBindings(w http.ResponseWriter, r *http.Request) {
	logrus := GetLogger(r)
	logrus.Trace("HandleListRoleBindings start")
	defer logrus.Trace("HandleListRoleBindings end")
	accessToken, err := common.GetAccesTokenFromAuthzHeader(r)
	if err != nil {
		logrus.Debugf("failed to get the access token from the request. Error: %q", err)
		w.Header().Set(common.AUTHENTICATE_HEADER, common.AUTHENTICATE_HEADER_MSG)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	routeVars := mux.Vars(r)
	idpId := routeVars[common.IDP_ID_ROUTE_VAR]
	idpUserId := routeVars[IDP_USER_ID_ROUTE_VAR]
	userId := idpId + common.DELIM + idpUserId

	logrus.Debug("trying to list all the role bindings for the user id:", userId)
	authServerUserId, err := GetAuthServerIdGivenUserId(accessToken, userId)
	if err != nil {
		logrus.Errorf("failed to get the authz server user id for the user id %s . Error: %q", userId, err)
		w.WriteHeader(http.StatusNotFound)
		return
	}
	logrus.Debug("found keycloak id for the user. Keycloak Id:", authServerUserId)

	roles, err := common.AuthServerClient.GetClientRolesByUserID(context.TODO(), accessToken, common.Config.AuthServerRealm, common.Config.M2kClientIdNotClientId, authServerUserId)
	if err != nil {
		logrus.Debug("failed to create the role binding at the authorization server. Error:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	roleIds := []string{}
	for _, role := range roles {
		tr := types.FromAuthServerRole(*role)
		roleIds = append(roleIds, tr.Id)
	}
	roleIdsBytes, err := json.Marshal(roleIds)
	if err != nil {
		logrus.Debug("Error:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set(common.CONTENT_TYPE_HEADER, common.CONTENT_TYPE_JSON)
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(roleIdsBytes); err != nil {
		logrus.Errorf("failed to write the response body. Error: %q", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

// HandlePatchRoleBindings handles patching the roles of a particular user
func HandlePatchRoleBindings(w http.ResponseWriter, r *http.Request) {
	logrus := GetLogger(r)
	logrus.Trace("HandlePatchRoleBindings start")
	defer logrus.Trace("HandlePatchRoleBindings end")
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
	patchRoles := struct {
		Op    string
		Roles []string
	}{}
	if err := json.Unmarshal(bodyBytes, &patchRoles); err != nil {
		logrus.Debugf("failed to unmarshal the request body as json into patchRoles. Error: %q", err)
		sendErrorJSON(w, "the request body is invalid.", http.StatusBadRequest)
		return
	}
	routeVars := mux.Vars(r)
	idpId := routeVars[common.IDP_ID_ROUTE_VAR]
	idpUserId := routeVars[IDP_USER_ID_ROUTE_VAR]
	userId := idpId + common.DELIM + idpUserId

	logrus.Debug("trying to update the role bindings for the user id:", userId, "with the operation:", patchRoles)
	authServerUserId, err := GetAuthServerIdGivenUserId(accessToken, userId)
	if err != nil {
		logrus.Errorf("failed to get the authz server user id for the user id %s . Error: %q", userId, err)
		// TODO: is this assumption ok?
		// assume the user doesn't exist
		user := gocloak.User{Username: &userId}
		if authServerUserId, err = common.AuthServerClient.CreateUser(context.TODO(), accessToken, common.Config.AuthServerRealm, user); err != nil {
			logrus.Errorf("failed to create the user with id %s on the authz server. Error: %q", userId, err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		logrus.Infof("failed to find the user with id %s . So we created a new user with the same id.", userId)
	}

	logrus.Debug("found keycloak id for the user. Keycloak Id:", authServerUserId)

	// Keycloak requires both the id and name of the role
	roles := []gocloak.Role{}
	for _, roleId := range patchRoles.Roles {
		roleInfo, err := common.AuthServerClient.GetClientRole(context.TODO(), accessToken, common.Config.AuthServerRealm, common.Config.M2kClientIdNotClientId, roleId)
		if err != nil {
			logrus.Debugf("failed to get information about the role with id %s from the authorization server. Error: %q\n", roleId, err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		roles = append(roles, gocloak.Role{ID: roleInfo.ID, Name: roleInfo.Name})
	}
	if patchRoles.Op == "add" {
		if err := common.AuthServerClient.AddClientRoleToUser(context.TODO(), accessToken, common.Config.AuthServerRealm, common.Config.M2kClientIdNotClientId, authServerUserId, roles); err != nil {
			logrus.Debug("failed to create the role binding at the authorization server. Error:", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	} else if patchRoles.Op == "remove" {
		if err := common.AuthServerClient.DeleteClientRoleFromUser(context.TODO(), accessToken, common.Config.AuthServerRealm, common.Config.M2kClientIdNotClientId, authServerUserId, roles); err != nil {
			logrus.Debug("failed to delete the role binding at the authorization server. Error:", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	} else if patchRoles.Op == "overwrite" {
		currentRoles, err := common.AuthServerClient.GetClientRolesByUserID(context.TODO(), accessToken, common.Config.AuthServerRealm, common.Config.M2kClientIdNotClientId, authServerUserId)
		if err != nil {
			logrus.Debug("failed to create the role binding at the authorization server. Error:", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		tRoles := []gocloak.Role{}
		for _, currentRole := range currentRoles {
			tRoles = append(tRoles, *currentRole)
		}
		if err := common.AuthServerClient.DeleteClientRoleFromUser(context.TODO(), accessToken, common.Config.AuthServerRealm, common.Config.M2kClientIdNotClientId, authServerUserId, tRoles); err != nil {
			logrus.Debug("failed to delete the role binding at the authorization server. Error:", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if err := common.AuthServerClient.AddClientRoleToUser(context.TODO(), accessToken, common.Config.AuthServerRealm, common.Config.M2kClientIdNotClientId, authServerUserId, roles); err != nil {
			logrus.Debug("failed to create the role binding at the authorization server. Error:", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	} else {
		logrus.Debug("trying to patch the roles for the user using an unsupported operation. Actual:", patchRoles)
		sendErrorJSON(w, `failed to update the role bindings. unknown operation. supported operations are "add", "remove" and "overwrite"`, http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// HandleCreateRoleBinding handles assigning a role to a particular user
func HandleCreateRoleBinding(w http.ResponseWriter, r *http.Request) {
	logrus := GetLogger(r)
	logrus.Trace("HandleCreateRoleBinding start")
	defer logrus.Trace("HandleCreateRoleBinding end")
	accessToken, err := common.GetAccesTokenFromAuthzHeader(r)
	if err != nil {
		logrus.Debugf("failed to get the access token from the request. Error: %q", err)
		w.Header().Set(common.AUTHENTICATE_HEADER, common.AUTHENTICATE_HEADER_MSG)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	routeVars := mux.Vars(r)
	idpId := routeVars[common.IDP_ID_ROUTE_VAR]
	idpUserId := routeVars[IDP_USER_ID_ROUTE_VAR]
	userId := idpId + common.DELIM + idpUserId
	roleId := routeVars[ROLE_ID_ROUTE_VAR]

	logrus.Debug("trying to create a role binding between the user id:", userId, "and role id:", roleId)
	authServerUserId, err := GetAuthServerIdGivenUserId(accessToken, userId)
	if err != nil {
		logrus.Errorf("failed to get the authz server user id for the user id %s . Error: %q", userId, err)
		// TODO: is this assumption ok?
		// assume the user doesn't exist
		user := gocloak.User{Username: &userId}
		if authServerUserId, err = common.AuthServerClient.CreateUser(context.TODO(), accessToken, common.Config.AuthServerRealm, user); err != nil {
			logrus.Errorf("failed to create the user with id %s on the authz server. Error: %q", userId, err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		logrus.Infof("failed to find the user with id %s . So we created a new user with the same id.", userId)
	}
	logrus.Debug("found keycloak id for the user. Keycloak Id:", authServerUserId)

	// Keycloak requires both the id and name of the role
	roleInfo, err := common.AuthServerClient.GetClientRole(context.TODO(), accessToken, common.Config.AuthServerRealm, common.Config.M2kClientIdNotClientId, roleId)
	if err != nil {
		logrus.Debugf("failed to get information about the role with id %s from the authorization server. Error: %q\n", roleId, err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	roles := []gocloak.Role{{ID: roleInfo.ID, Name: roleInfo.Name}}
	if err := common.AuthServerClient.AddClientRoleToUser(context.TODO(), accessToken, common.Config.AuthServerRealm, common.Config.M2kClientIdNotClientId, authServerUserId, roles); err != nil {
		logrus.Debug("failed to create the role binding at the authorization server. Error:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// HandleDeleteRoleBinding handles removing a role from a particular user
func HandleDeleteRoleBinding(w http.ResponseWriter, r *http.Request) {
	logrus := GetLogger(r)
	logrus.Trace("HandleDeleteRoleBinding start")
	defer logrus.Trace("HandleDeleteRoleBinding end")
	accessToken, err := common.GetAccesTokenFromAuthzHeader(r)
	if err != nil {
		logrus.Debugf("failed to get the access token from the request. Error: %q", err)
		w.Header().Set(common.AUTHENTICATE_HEADER, common.AUTHENTICATE_HEADER_MSG)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	routeVars := mux.Vars(r)
	idpId := routeVars[common.IDP_ID_ROUTE_VAR]
	idpUserId := routeVars[IDP_USER_ID_ROUTE_VAR]
	userId := idpId + common.DELIM + idpUserId
	roleId := routeVars[ROLE_ID_ROUTE_VAR]

	logrus.Debug("trying to delete a role binding between the user id:", userId, "and role id:", roleId)
	authServerUserId, err := GetAuthServerIdGivenUserId(accessToken, userId)
	if err != nil {
		logrus.Errorf("failed to get the authz server user id for the user id %s . Error: %q", userId, err)
		w.WriteHeader(http.StatusNotFound)
		return
	}
	logrus.Debug("found keycloak id for the user. Keycloak Id:", authServerUserId)

	// Keycloak requires both the id and name of the role
	roleInfo, err := common.AuthServerClient.GetClientRole(context.TODO(), accessToken, common.Config.AuthServerRealm, common.Config.M2kClientIdNotClientId, roleId)
	if err != nil {
		logrus.Debugf("failed to get information about the role with id %s from the authorization server. Error: %q\n", roleId, err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	roles := []gocloak.Role{{ID: roleInfo.ID, Name: roleInfo.Name}}
	if err := common.AuthServerClient.DeleteClientRoleFromUser(context.TODO(), accessToken, common.Config.AuthServerRealm, common.Config.M2kClientIdNotClientId, authServerUserId, roles); err != nil {
		logrus.Debug("failed to delete the role binding at the authorization server. Error:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GetAuthServerIdGivenUserId returns the authz server Id of the user given the user id used in the Move2Kube API URL endpoints
func GetAuthServerIdGivenUserId(accessToken string, userId string) (string, error) {
	logrus.Trace("GetAuthServerIdGivenUserId start")
	defer logrus.Trace("GetAuthServerIdGivenUserId end")
	userParams := gocloak.GetUsersParams{Username: &userId}
	userInfos, err := common.AuthServerClient.GetUsers(context.TODO(), accessToken, common.Config.AuthServerRealm, userParams)
	if err != nil {
		return "", fmt.Errorf("failed to get the users with the filter %s . Error: %q", userParams.String(), err)
	}
	if len(userInfos) != 1 {
		return "", fmt.Errorf("expected there to be exactly one user with the user id %s . Actual: %+v", userId, userInfos)
	}
	if userInfos[0].ID == nil {
		return "", fmt.Errorf("expected the user with the user id %s to have a corresponding keycloak Id. Actual: %+v", userId, userInfos[0])
	}
	return *userInfos[0].ID, nil
}
