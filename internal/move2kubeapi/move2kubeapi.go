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
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/konveyor/move2kube-api/internal/application"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cast"
)

var m2kapp application.IApplication = application.NewFileSystem()

func swagger(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Swagger will come here!")
}

func support(w http.ResponseWriter, r *http.Request) {
	responseBody := m2kapp.GetSupportInfo()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(responseBody); err != nil {
		log.Errorf("Failed to write support information. Error: %q", err)
	}
}

func getApplications(w http.ResponseWriter, r *http.Request) {
	applications := m2kapp.GetApplications()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	err := json.NewEncoder(w).Encode(application.Applications{Applications: applications})
	if err != nil {
		log.Errorf("Error while getting application list : %s", err)
	}
}

func createApplication(w http.ResponseWriter, r *http.Request) {
	var newApp application.Application
	/*reqBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Fprintf(w, "Unable to read data")
	}*/
	//json.Unmarshal(reqBody, &newApp)
	/*q := r.URL.Query()
	newApp.Name = q.Get("name")*/
	newApp.Name = r.FormValue("name")
	newApp.Status = []application.ApplicationStatus{}
	err := m2kapp.NewApplication(newApp)
	if err != nil {
		if err.Error() == "Already exists." {
			log.Errorf("Application already exists : %s", err)
			w.WriteHeader(http.StatusAlreadyReported)
		} else {
			log.Errorf("Unable to create application : %s", err)
			w.WriteHeader(http.StatusBadRequest)
		}
	} else {
		w.WriteHeader(http.StatusCreated)
		err = json.NewEncoder(w).Encode(newApp)
		if err != nil {
			log.Errorf("Error while creating application : %s", err)
		}
	}
}

func getApplication(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	app, err := m2kapp.GetApplication(name)
	if err != nil {
		log.Errorf("Error while fetching application : %s : %s", name, err)
		w.WriteHeader(http.StatusNotFound)
	} else {
		log.Debugf("Fetched application : %s", name)
		w.WriteHeader(http.StatusOK)
		err = json.NewEncoder(w).Encode(app)
		if err != nil {
			log.Errorf("Error while getting application : %s", err)
		}
	}
}

func deleteApplication(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	err := m2kapp.DeleteApplication(name)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
	} else {
		w.WriteHeader(http.StatusOK)
		log.Infof("Application %s has been deleted successfully", name)
	}
}

func uploadAsset(w http.ResponseWriter, r *http.Request, isCustomization bool) {
	name := mux.Vars(r)["name"]
	file, handler, err := r.FormFile("file")
	if err != nil {
		log.Errorf("Did not get asset : %s", err)
		w.WriteHeader(http.StatusNotFound)
		return
	}
	defer file.Close()
	if err := m2kapp.UploadAsset(name, handler.Filename, file, isCustomization); err != nil {
		log.Errorf("Could not update with asset : %s", err)
		w.WriteHeader(http.StatusGone)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "File "+handler.Filename+" Uploaded successfully")
	log.Infof("Asset %s uploaded successfully for app %s", handler.Filename, name)
}

func getAssetsList(w http.ResponseWriter, r *http.Request, isCustomization bool) {
	name := mux.Vars(r)["name"]
	assets, err := m2kapp.GetAssetsList(name, isCustomization)
	if err != nil || assets == nil {
		log.Errorf("Could not get the assets/customizations for the app %s . Error: %q", name, err)
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(assets); err != nil {
		log.Errorf("failed to marhsal the assets/customizations list %+v to json. Error: %q", assets, err)
	}
}

func getAsset(w http.ResponseWriter, r *http.Request, isCustomization bool) {
	name := mux.Vars(r)["name"]
	asset := ""
	if isCustomization {
		asset = mux.Vars(r)["customization"]
	} else {
		asset = mux.Vars(r)["asset"]
	}
	file, filename, err := m2kapp.GetAsset(name, asset, isCustomization)
	if err != nil || file == nil {
		log.Errorf("Could not get asset %s for the app %s . Error: %q", asset, name, err)
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename="+filename)
	if _, err := io.Copy(w, file); err != nil {
		log.Errorf("failed to send the asset/customization to the client. Error: %q", err)
	}
}

func deleteAsset(w http.ResponseWriter, r *http.Request, isCustomization bool) {
	name := mux.Vars(r)["name"]
	asset := ""
	if isCustomization {
		asset = mux.Vars(r)["customization"]
	} else {
		asset = mux.Vars(r)["asset"]
	}
	if err := m2kapp.DeleteAsset(name, asset, isCustomization); err != nil {
		log.Errorf("Could not delete asset : %s", err)
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "Asset "+asset+" deleted successfully")
	log.Infof("Asset %s deleted successfully for app %s", asset, name)
}

func generateTargetArtifacts(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	plan := r.FormValue("plan")

	artifactName := name + "-" + cast.ToString(time.Now().Unix())
	log.Infof("Artifact Name:%s", artifactName)

	keys, ok := r.URL.Query()["debug"]
	var debugFlag bool
	if !ok || len(keys[0]) == 0 {
		log.Debugf("Query parameter debug : false")
	} else {
		var err error
		debugFlag, err = cast.ToBoolE(keys[0])
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			bodyBytes, err := json.Marshal(map[string]string{"error": "the debug parameter must be boolean"})
			if err != nil {
				log.Error(err)
				return
			}
			w.Write(bodyBytes)
		}
		log.Debugf("Query parameter debug : %v", debugFlag)
	}
	if err := m2kapp.Transform(name, artifactName, plan, debugFlag); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, "Could not start transformation : "+err.Error())
		return
	}
	w.WriteHeader(http.StatusAccepted)
	_, _ = io.WriteString(w, artifactName)
}

func getTargetArtifacts(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	artifact := mux.Vars(r)["artifact"]

	file, filename := m2kapp.GetTargetArtifacts(name, artifact)
	if filename == "error" {
		log.Errorf("Artifact %s not found. Start Transformation.", artifact)
		w.WriteHeader(http.StatusBadRequest)
		return
	} else if filename == "ongoing" {
		log.Infof("Artifact generation ongoing : %s", name)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Content-Disposition", "attachment; filename="+filename)
	w.Header().Set("Content-Type", r.Header.Get("Content-Type"))
	w.WriteHeader(http.StatusOK)
	_, err := io.Copy(w, file)
	if err != nil {
		log.Errorf("Error while getting asset : %s", err)
	}
}

func getTargetArtifactsList(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]

	artifacts := m2kapp.GetTargetArtifactsList(name)
	if artifacts == nil {
		log.Errorf("Could not get artifacts")
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", r.Header.Get("Content-Type"))
	err := json.NewEncoder(w).Encode(artifacts)
	if err != nil {
		log.Errorf("Error while getting target artifacts list : %s", err)
	}
}

func deleteTargetArtifacts(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	artifact := mux.Vars(r)["artifact"]

	err := m2kapp.DeleteTargetArtifacts(name, artifact)
	if err != nil {
		log.Errorf("Could not delete artifact : %s", err)
		w.WriteHeader(http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "Asset "+artifact+" deleted successfully")
	log.Infof("Asset %s deleted successfully for app %s", artifact, name)
}

func startPlan(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	keys, ok := r.URL.Query()["debug"]
	var debugFlag bool
	if !ok || len(keys[0]) == 0 {
		log.Infof("Query parameter debug : false")
	} else {
		var err error
		debugFlag, err = cast.ToBoolE(keys[0])
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			bodyBytes, err := json.Marshal(map[string]string{"error": "the debug parameter must be boolean"})
			if err != nil {
				log.Error(err)
				return
			}
			w.Write(bodyBytes)
		}
		log.Infof("Query parameter debug : %v", debugFlag)
	}
	if err := m2kapp.GeneratePlan(name, debugFlag); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, "Could not start plan : "+err.Error())
		return
	}
	w.WriteHeader(http.StatusAccepted)
	_, _ = io.WriteString(w, "Planning started!")
}

func updatePlan(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	planfile := r.FormValue("plan")

	err := m2kapp.UpdatePlan(name, planfile)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, "Could not start plan : "+err.Error())
	} else {
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, "Planning started!")
	}
}

func getPlan(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]

	plan, filename := m2kapp.GetPlan(name)
	if filename == "" {
		log.Debugf("Plan not found. Start Planning.")
		w.WriteHeader(http.StatusNotFound)
		return
	} else if filename == "ongoing" {
		log.Infof("Plan generation ongoing : %s", name)
		w.WriteHeader(http.StatusAccepted)
		return
	}
	w.Header().Set("Content-Disposition", "attachment; filename="+filename)
	w.Header().Set("Content-Type", r.Header.Get("Content-Type"))
	_, err := io.Copy(w, plan)
	if err != nil {
		log.Errorf("Error while getting plan : %s", err)
	}
}

func deletePlan(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]

	err := m2kapp.DeletePlan(name)
	if err != nil {
		log.Infof("Plan not found. Start Planning.")
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func getQuestion(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	artifacts := mux.Vars(r)["artifacts"]
	problem, err := m2kapp.GetQuestion(name, artifacts)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, problem)
}

func postSolution(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	artifacts := mux.Vars(r)["artifacts"]
	solution, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	solutionstr := string(solution)
	err = m2kapp.PostSolution(name, artifacts, solutionstr)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
	} else {
		w.WriteHeader(http.StatusOK)
	}
}

func download(w http.ResponseWriter, r *http.Request) {
	file, filename := m2kapp.Download()
	if file == nil {
		log.Errorf("Could not get binary")
		w.WriteHeader(http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Disposition", "attachment; filename="+filename)
	w.Header().Set("Content-Type", r.Header.Get("Content-Type"))
	_, err := io.Copy(w, file)
	if err != nil {
		log.Errorf("Error during app download : %s", err)
	}
}

// Serve serves the api server
func Serve(port int) {
	router := mux.NewRouter().StrictSlash(true)
	//router.Handle("/", handlers.LoggingHandler(os.Stdout, http.HandlerFunc(swagger)))
	router.HandleFunc("/", swagger)
	router.HandleFunc("/api/v1/", swagger)
	router.HandleFunc("/api/v1/support", support)

	router.HandleFunc("/api/v1/download", download).Methods("GET")
	router.HandleFunc("/api/v1/applications", createApplication).Methods("POST")
	router.HandleFunc("/api/v1/applications", getApplications).Methods("GET")
	router.HandleFunc("/api/v1/applications/{name}", getApplication).Methods("GET")
	router.HandleFunc("/api/v1/applications/{name}", deleteApplication).Methods("DELETE")

	router.HandleFunc("/api/v1/applications/{name}/assets", func(w http.ResponseWriter, r *http.Request) { getAssetsList(w, r, false) }).Methods("GET")
	router.HandleFunc("/api/v1/applications/{name}/assets", func(w http.ResponseWriter, r *http.Request) { uploadAsset(w, r, false) }).Methods("POST")
	router.HandleFunc("/api/v1/applications/{name}/assets/{asset}", func(w http.ResponseWriter, r *http.Request) { deleteAsset(w, r, false) }).Methods("DELETE")
	router.HandleFunc("/api/v1/applications/{name}/assets/{asset}", func(w http.ResponseWriter, r *http.Request) { getAsset(w, r, false) }).Methods("GET")

	router.HandleFunc("/api/v1/applications/{name}/customizations", func(w http.ResponseWriter, r *http.Request) { getAssetsList(w, r, true) }).Methods("GET")
	router.HandleFunc("/api/v1/applications/{name}/customizations", func(w http.ResponseWriter, r *http.Request) { uploadAsset(w, r, true) }).Methods("POST")
	router.HandleFunc("/api/v1/applications/{name}/customizations/{customization}", func(w http.ResponseWriter, r *http.Request) { deleteAsset(w, r, true) }).Methods("DELETE")
	router.HandleFunc("/api/v1/applications/{name}/customizations/{customization}", func(w http.ResponseWriter, r *http.Request) { getAsset(w, r, true) }).Methods("GET")

	router.HandleFunc("/api/v1/applications/{name}/targetartifacts", getTargetArtifactsList).Methods("GET")
	router.HandleFunc("/api/v1/applications/{name}/targetartifacts", generateTargetArtifacts).Methods("POST")
	router.HandleFunc("/api/v1/applications/{name}/targetartifacts/{artifact}", getTargetArtifacts).Methods("GET")
	router.HandleFunc("/api/v1/applications/{name}/targetartifacts/{artifact}", deleteTargetArtifacts).Methods("DELETE")

	router.HandleFunc("/api/v1/applications/{name}/plan", getPlan).Methods("GET")
	router.HandleFunc("/api/v1/applications/{name}/plan", startPlan).Methods("POST")
	router.HandleFunc("/api/v1/applications/{name}/plan", updatePlan).Methods("PUT")
	router.HandleFunc("/api/v1/applications/{name}/plan", deletePlan).Methods("DELETE")

	router.HandleFunc("/api/v1/applications/{name}/targetartifacts/{artifacts}/problems/current", getQuestion).Methods("GET")
	router.HandleFunc("/api/v1/applications/{name}/targetartifacts/{artifacts}/problems/current/solution", postSolution).Methods("POST")

	log.Infof("Starting Move2Kube API server at port: %d", port)
	log.Fatal(http.ListenAndServe(":"+cast.ToString(port), router))
}
