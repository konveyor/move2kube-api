/*
Copyright IBM Corporation 2020

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

package move2kubeapi

import (
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/gorilla/mux"
	"github.com/konveyor/move2kube-api/assets"
	"github.com/konveyor/move2kube-api/internal/common"
	"github.com/konveyor/move2kube-api/internal/move2kubeapi/handlers"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cast"
)

// Serve starts the Move2Kube API server.
func Serve() error {
	if err := handlers.Setup(); err != nil {
		return fmt.Errorf("failed to setup the handlers. Error: %q", err)
	}

	router := mux.NewRouter()
	router.Use(handlers.GetLoggingMiddleWare)
	router.Use(handlers.GetRemoveTrailingSlashMiddleWare)

	// dynamic routes
	if common.Config.AuthEnabled {
		router.HandleFunc(common.LOGIN_PATH, handlers.HandleLogin).Methods("GET")
		router.HandleFunc(common.LOGIN_CALLBACK_PATH, handlers.HandleLoginCallback).Methods("GET")
		router.HandleFunc("/auth/logout", handlers.HandleLogout).Methods("POST")
		router.HandleFunc("/auth/user-profile", handlers.HandleUserProfile).Methods("GET")
	}

	// API routes
	router.Handle("/api/v1", http.RedirectHandler("/swagger/openapi.json", http.StatusFound)).Methods("GET") // openapi v3 json
	apiRouter := router.PathPrefix("/api/v1").Subrouter()

	if common.Config.AuthEnabled {
		apiRouter.Use(handlers.GetAuthorizationMiddleWare)

		// admin
		apiRouter.HandleFunc("/token", handlers.HandleGetAccessToken).Methods("POST")

		// roles
		apiRouter.HandleFunc("/roles", handlers.HandleListRoles).Methods("GET")
		apiRouter.HandleFunc("/roles", handlers.HandleCreateRole).Methods("POST")
		apiRouter.HandleFunc("/roles/{role-id}", handlers.HandleReadRole).Methods("GET")
		apiRouter.HandleFunc("/roles/{role-id}", handlers.HandleUpdateRole).Methods("PUT")
		apiRouter.HandleFunc("/roles/{role-id}", handlers.HandleDeleteRole).Methods("DELETE")

		// role-bindings
		apiRouter.HandleFunc("/idps/{idp-id}/users/{user-id}/roles", handlers.HandleListRoleBindings).Methods("GET")
		apiRouter.HandleFunc("/idps/{idp-id}/users/{user-id}/roles", handlers.HandlePatchRoleBindings).Methods("PATCH")
		apiRouter.HandleFunc("/idps/{idp-id}/users/{user-id}/roles/{role-id}", handlers.HandleCreateRoleBinding).Methods("PUT")
		apiRouter.HandleFunc("/idps/{idp-id}/users/{user-id}/roles/{role-id}", handlers.HandleDeleteRoleBinding).Methods("DELETE")
	}

	// general
	apiRouter.HandleFunc("/support", handlers.HandleSupport).Methods("GET")

	// workspaces
	apiRouter.HandleFunc("/workspaces", handlers.HandleListWorkspaces).Methods("GET")
	apiRouter.HandleFunc("/workspaces", handlers.HandleCreateWorkspace).Methods("POST")
	apiRouter.HandleFunc("/workspaces/{work-id}", handlers.HandleReadWorkspace).Methods("GET")
	apiRouter.HandleFunc("/workspaces/{work-id}", handlers.HandleUpdateWorkspace).Methods("PUT")
	apiRouter.HandleFunc("/workspaces/{work-id}", handlers.HandleDeleteWorkspace).Methods("DELETE")

	// projects
	apiRouter.HandleFunc("/workspaces/{work-id}/projects", handlers.HandleListProjects).Methods("GET")
	apiRouter.HandleFunc("/workspaces/{work-id}/projects", handlers.HandleCreateProject).Methods("POST")
	apiRouter.HandleFunc("/workspaces/{work-id}/projects/{proj-id}", handlers.HandleReadProject).Methods("GET")
	apiRouter.HandleFunc("/workspaces/{work-id}/projects/{proj-id}", handlers.HandleDeleteProject).Methods("DELETE")

	// project inputs
	apiRouter.HandleFunc("/workspaces/{work-id}/projects/{proj-id}/inputs", handlers.HandleCreateProjectInput).Methods("POST")
	apiRouter.HandleFunc("/workspaces/{work-id}/projects/{proj-id}/inputs/{input-id}", handlers.HandleReadProjectInput).Methods("GET")
	apiRouter.HandleFunc("/workspaces/{work-id}/projects/{proj-id}/inputs/{input-id}", handlers.HandleDeleteProjectInput).Methods("DELETE")

	// plan
	apiRouter.HandleFunc("/workspaces/{work-id}/projects/{proj-id}/plan", handlers.HandleStartPlanning).Methods("POST")
	apiRouter.HandleFunc("/workspaces/{work-id}/projects/{proj-id}/plan", handlers.HandleReadPlan).Methods("GET")
	apiRouter.HandleFunc("/workspaces/{work-id}/projects/{proj-id}/plan", handlers.HandleUpdatePlan).Methods("PUT")
	apiRouter.HandleFunc("/workspaces/{work-id}/projects/{proj-id}/plan", handlers.HandleDeletePlan).Methods("DELETE")

	// project outputs
	apiRouter.HandleFunc("/workspaces/{work-id}/projects/{proj-id}/outputs", handlers.HandleStartTransformation).Methods("POST")
	apiRouter.HandleFunc("/workspaces/{work-id}/projects/{proj-id}/outputs/{output-id}", handlers.HandleReadProjectOutput).Methods("GET")
	apiRouter.HandleFunc("/workspaces/{work-id}/projects/{proj-id}/outputs/{output-id}", handlers.HandleDeleteProjectOutput).Methods("DELETE")

	// QA
	apiRouter.HandleFunc("/workspaces/{work-id}/projects/{proj-id}/outputs/{output-id}/problems/current", handlers.HandleGetQuestion).Methods("GET")
	apiRouter.HandleFunc("/workspaces/{work-id}/projects/{proj-id}/outputs/{output-id}/problems/current/solution", handlers.HandlePostSolution).Methods("POST")

	if common.Config.AuthEnabled {
		// Reverse proxy the authorization server. Required for login.
		backendURL, err := url.Parse(common.Config.AuthServer)
		if err != nil {
			return fmt.Errorf("failed to parse the authorization server URL as a URL. Error: %q", err)
		}
		revProxy := httputil.NewSingleHostReverseProxy(backendURL)
		oldDirector := revProxy.Director
		revProxy.Director = func(req *http.Request) {
			logrus.Debugf("reverse proxy, request before modification: %+v", req)
			oldDirector(req)
			req.Host = req.URL.Host
			if req.URL.Path == backendURL.Path+"/" {
				req.URL.Path = backendURL.Path
				req.URL.RawPath = backendURL.Path
			}
			logrus.Debugf("reverse proxy, request after modification: %+v", req)
		}
		router.PathPrefix(common.Config.AuthServerBasePath).Handler(revProxy)
	}

	// static routes
	// swagger UI
	swaggerDir, _ := fs.Sub(assets.SwaggerUI, "swagger")
	router.Handle("/swagger", http.RedirectHandler("/swagger/", http.StatusMovedPermanently))
	router.PathPrefix("/swagger/").Handler(http.StripPrefix("/swagger", http.FileServer(http.FS(swaggerDir)))).Methods("GET")

	// move2kube UI
	staticFilesDir := common.Config.StaticFilesDir
	if staticFilesDir != "" {
		finfo, err := os.Stat(staticFilesDir)
		if err != nil {
			if os.IsNotExist(err) {
				log.Fatalf("the static files directory %s does not exist.", staticFilesDir)
			}
			log.Fatalf("failed to stat the static files directory at path %s . Error: %q", staticFilesDir, err)
		}
		if !finfo.IsDir() {
			return fmt.Errorf("the path %s points to a file. Expected a directory containing static files to be served", staticFilesDir)
		}
		m2kUI := http.FileServer(http.Dir(staticFilesDir))
		letReactRouterHandleIt := func(w http.ResponseWriter, r *http.Request) bool {
			if r.Method != "GET" {
				return false
			}
			accepting := r.Header[http.CanonicalHeaderKey("Accept")]
			found := false
			for _, aa := range accepting {
				if strings.Contains(aa, "text/html") {
					found = true
					break
				}
			}
			if !found {
				return false
			}
			w.Header().Set(common.CONTENT_TYPE_HEADER, "text/html")
			w.WriteHeader(http.StatusOK)
			http.ServeFile(w, r, filepath.Join(staticFilesDir, "index.html"))
			return true
		}
		router.PathPrefix("/").Handler(handle404(m2kUI, letReactRouterHandleIt)).Methods("GET")
	}

	logrus.Infof("Starting Move2Kube API server at port: %d", common.Config.Port)
	if err := http.ListenAndServe(":"+cast.ToString(common.Config.Port), router); err != nil {
		return fmt.Errorf("failed to listen and serve on port %d . Error: %q", common.Config.Port, err)
	}
	return nil
}

// let react router handle unrecognized text/html GET requests

type hijack404 struct {
	http.ResponseWriter
	R         *http.Request
	Handle404 func(w http.ResponseWriter, r *http.Request) bool
}

func (h *hijack404) WriteHeader(code int) {
	if code == 404 && h.Handle404(h.ResponseWriter, h.R) {
		panic(h)
	}
	h.ResponseWriter.WriteHeader(code)
}

func handle404(handler http.Handler, handle404 func(w http.ResponseWriter, r *http.Request) bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hijack := &hijack404{ResponseWriter: w, R: r, Handle404: handle404}
		defer func() {
			if p := recover(); p != nil {
				if p == hijack {
					return
				}
				panic(p)
			}
		}()
		handler.ServeHTTP(hijack, r)
	})
}
