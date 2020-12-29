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

package application

import (
	"io"
)

const (
	// appName stores the application name
	appName = "move2kube"
	// appNameShort stores the application shortname
	appNameShort = "m2k"
)

// IApplication defines interfact that can manage Move2Kube applications
type IApplication interface {
	Download() (file io.Reader, filename string)
	GetApplications() []Application
	NewApplication(Application) error
	GetApplication(name string) (Application, error)
	DeleteApplication(name string) error
	UploadAsset(appName string, filename string, file io.Reader) error
	DeleteAsset(appName, asset string) error
	GetAsset(appName, asset string) (file io.Reader, filename string)
	GetAssetsList(appName string) (assets []string)
	Translate(appname, artifactName, plan string, debugMode bool) error
	GetTargetArtifacts(appName, artifact string) (file io.Reader, filename string) // Return "ongoing" as filename if artifacts are in the process of generation
	GetTargetArtifactsList(appName string) (artifacts []string)
	DeleteTargetArtifacts(appName string, asset string) error
	GeneratePlan(appname string, debugMode bool) error
	DeletePlan(appname string) error
	UpdatePlan(appname, plan string) error
	GetPlan(appName string) (file io.Reader, filename string) // Return "ongoing" as filename if plan is in generation
	GetQuestion(appName string, artifact string) (problem string, err error)
	PostSolution(appName string, artifact string, solution string) error
}

// ApplicationStatus stores the current application status
type ApplicationStatus string

const (
	// ApplicationStatusPlan indicates the application has a plan
	ApplicationStatusPlan ApplicationStatus = "plan"
	// ApplicationStatusPlanning indicates the application is currently computing a plan
	ApplicationStatusPlanning ApplicationStatus = "planning"
	// ApplicationStatusAssets indicates the application has assets
	ApplicationStatusAssets ApplicationStatus = "assets"
	// ApplicationStatusArtifacts indicates the application has application artifacts generated
	ApplicationStatusArtifacts ApplicationStatus = "artifacts"
)

// Application stores the application metadata
type Application struct {
	Name   string              `json:"name"`
	Status []ApplicationStatus `json:"status"`
}

// Applications stores the list of application metadatas
type Applications struct {
	Applications []Application `json:"applications"`
}
