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

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/konveyor/move2kube-api/internal/application"
	log "github.com/sirupsen/logrus"

	"github.com/gorilla/mux"
)

var m2kapp application.IApplication

func swagger(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Swagger will come here!")
}

func GetApplications(w http.ResponseWriter, r *http.Request) {
	applications := m2kapp.GetApplications()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	err := json.NewEncoder(w).Encode(application.Applications{Applications: applications})
	if err != nil {
		log.Errorf("Error while getting application list : %s", err)
	}
}

func CreateApplication(w http.ResponseWriter, r *http.Request) {
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

func GetApplication(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	app, err := m2kapp.GetApplication(name)
	if err != nil {
		log.Errorf("Error while fetching application : %s : %s", name, err)
		w.WriteHeader(http.StatusNotFound)
	} else {
		log.Infof("Fetched application : %s", name)
		w.WriteHeader(http.StatusOK)
		err = json.NewEncoder(w).Encode(app)
		if err != nil {
			log.Errorf("Error while getting application : %s", err)
		}
	}
}

func DeleteApplication(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	err := m2kapp.DeleteApplication(name)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
	} else {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Application %v has been deleted successfully", name)
	}
}

func UploadAsset(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	file, handler, err := r.FormFile("file")
	if err != nil {
		log.Errorf("Did not get asset : %s", err)
		w.WriteHeader(http.StatusNotFound)
		return
	}
	defer file.Close()

	err = m2kapp.UploadAsset(name, handler.Filename, file)
	if err != nil {
		log.Errorf("Could not update with asset : %s", err)
		w.WriteHeader(http.StatusGone)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "File "+handler.Filename+" Uploaded successfully")
	log.Infof("Asset %s uploaded successfully for app %s", handler.Filename, name)
}

func GetAssetsList(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]

	assets := m2kapp.GetAssetsList(name)
	if assets == nil {
		log.Errorf("Could not get assets")
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", r.Header.Get("Content-Type"))
	err := json.NewEncoder(w).Encode(assets)
	if err != nil {
		log.Errorf("Error while getting assets list : %s", err)
	}
}

func GetAsset(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	asset := mux.Vars(r)["asset"]

	file, filename := m2kapp.GetAsset(name, asset)
	if file == nil {
		log.Errorf("Could not get asset %s", asset)
		w.WriteHeader(http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Disposition", "attachment; filename="+filename)
	w.Header().Set("Content-Type", r.Header.Get("Content-Type"))
	_, err := io.Copy(w, file)
	if err != nil {
		log.Errorf("Error while getting asset : %s", err)
	}
}

func DeleteAsset(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	asset := mux.Vars(r)["asset"]

	err := m2kapp.DeleteAsset(name, asset)
	if err != nil {
		log.Errorf("Could not delete asset : %s", err)
		w.WriteHeader(http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "Asset "+asset+" deleted successfully")
	log.Infof("Asset %s deleted successfully for app %s", asset, name)
}

func GenerateTargetArtifacts(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	plan := r.FormValue("plan")

	re := regexp.MustCompile(`artifacttype:\\s.*`)
	artifactTypematch := re.FindString(plan)
	artifactType := "helm"
	if strings.HasSuffix(artifactTypematch, "knative") {
		artifactType = "knative"
	} else if strings.HasSuffix(artifactTypematch, "k8") {
		artifactType = "k8"
	}
	t := time.Now()
	artifactName := name + "_" + artifactType + "_" + strconv.FormatInt(t.Unix(), 10)
	log.Infof("Artifact Name:%s", artifactName)

	err := m2kapp.Translate(name, artifactName, plan)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, "Could not start translation : "+err.Error())
	} else {
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, artifactName)
	}
}

func GetTargetArtifacts(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	artifact := mux.Vars(r)["artifact"]

	file, filename := m2kapp.GetTargetArtifacts(name, artifact)
	if filename == "error" {
		log.Errorf("Artifact %s not found. Start Translation.", artifact)
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

func GetTargetArtifactsList(w http.ResponseWriter, r *http.Request) {
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

func DeleteTargetArtifacts(w http.ResponseWriter, r *http.Request) {
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

func StartPlan(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]

	err := m2kapp.GeneratePlan(name)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, "Could not start plan : "+err.Error())
	} else {
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, "Planning started!")
	}
}

func UpdatePlan(w http.ResponseWriter, r *http.Request) {
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

func GetPlan(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]

	plan, filename := m2kapp.GetPlan(name)
	if filename == "" {
		log.Errorf("Plan not found. Start Planning.")
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

func DeletePlan(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]

	err := m2kapp.DeletePlan(name)
	if err != nil {
		log.Errorf("Plan not found. Start Planning.")
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func GetQuestion(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	artifacts := mux.Vars(r)["artifacts"]
	problem, err := m2kapp.GetQuestion(name, artifacts)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
	} else {
		if problem == "" {
			w.WriteHeader(http.StatusAlreadyReported)
		} else {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, problem)
		}
	}
}

func PostSolution(w http.ResponseWriter, r *http.Request) {
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
		w.WriteHeader(http.StatusNotFound)
	} else {
		w.WriteHeader(http.StatusOK)
	}
}

func Download(w http.ResponseWriter, r *http.Request) {
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

func main() {
	mode := flag.String("mode", "filesystem", "filesystem or operator")

	switch *mode {
	case "filesystem":
		m2kapp = application.NewFileSystem()
	case "operator":
		m2kapp = application.NewFileSystem()
	default:
		m2kapp = application.NewFileSystem()
	}

	router := mux.NewRouter().StrictSlash(true)
	//router.Handle("/", handlers.LoggingHandler(os.Stdout, http.HandlerFunc(swagger)))
	router.HandleFunc("/", swagger)
	router.HandleFunc("/api/v1/", swagger)

	router.HandleFunc("/api/v1/download", Download).Methods("GET")
	router.HandleFunc("/api/v1/applications", CreateApplication).Methods("POST")
	router.HandleFunc("/api/v1/applications", GetApplications).Methods("GET")
	router.HandleFunc("/api/v1/applications/{name}", GetApplication).Methods("GET")
	router.HandleFunc("/api/v1/applications/{name}", DeleteApplication).Methods("DELETE")

	router.HandleFunc("/api/v1/applications/{name}/assets", GetAssetsList).Methods("GET")
	router.HandleFunc("/api/v1/applications/{name}/assets", UploadAsset).Methods("POST")
	router.HandleFunc("/api/v1/applications/{name}/assets/{asset}", DeleteAsset).Methods("DELETE")
	router.HandleFunc("/api/v1/applications/{name}/assets/{asset}", GetAsset).Methods("GET")

	router.HandleFunc("/api/v1/applications/{name}/targetartifacts", GetTargetArtifactsList).Methods("GET")
	router.HandleFunc("/api/v1/applications/{name}/targetartifacts", GenerateTargetArtifacts).Methods("POST")
	router.HandleFunc("/api/v1/applications/{name}/targetartifacts/{artifact}", GetTargetArtifacts).Methods("GET")
	router.HandleFunc("/api/v1/applications/{name}/targetartifacts/{artifact}", DeleteTargetArtifacts).Methods("DELETE")

	router.HandleFunc("/api/v1/applications/{name}/plan", GetPlan).Methods("GET")
	router.HandleFunc("/api/v1/applications/{name}/plan", StartPlan).Methods("POST")
	router.HandleFunc("/api/v1/applications/{name}/plan", UpdatePlan).Methods("PUT")
	router.HandleFunc("/api/v1/applications/{name}/plan", DeletePlan).Methods("DELETE")

	router.HandleFunc("/api/v1/applications/{name}/targetartifacts/{artifacts}/problems/current", GetQuestion).Methods("GET")
	router.HandleFunc("/api/v1/applications/{name}/targetartifacts/{artifacts}/problems/current/solution", PostSolution).Methods("POST")

	log.Fatal(http.ListenAndServe(":8080", router))
}
