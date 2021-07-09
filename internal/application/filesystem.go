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
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/konveyor/move2kube-api/cmd/version"
	"github.com/konveyor/move2kube-api/internal/types"
	archiver "github.com/mholt/archiver/v3"
	"github.com/phayes/freeport"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

const (
	assetsDirectory                         = string(ApplicationStatusAssets)
	artifactsDirectory                      = string(ApplicationStatusArtifacts)
	expandedDirectory                       = "expanded"
	archivesDirectory                       = "archives"
	srcDirectory                            = "source"
	customizationsDirectory                 = string(ApplicationStatusCustomizations)
	containersDirectory                     = "containers"
	m2kplanfilename                         = appNameShort + ".plan"
	m2kQAServerMetadataFile                 = "." + appNameShort + "qa"
	m2kPlanOngoingFile                      = "." + appNameShort + "plan"
	apiServerPort                           = 8080
	timestampRegex                          = `time="\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z"`
	loglevelRegex                           = `level=([a-z]+) `
	newfilesMetadataFileName                = "newfiles.txt"
	defaultDirectoryPermissions os.FileMode = 0777
	defaultFilePermissions      os.FileMode = 0777
)

var (
	validArchiveExts = []string{".zip", ".tar", ".tgz", ".gz"}
)

/*
Workspace Folder Structure
--------------------------
We make a copy of the entire source and config folders whenever a new run is triggered (by clicking the Transform button)
to avoid race conditions with some user changing the source folder while a plan or transformation is in progress.

It also allows for resuming previous runs. We remove the output folder if it exists (while preserving the m2kqaconfig file).
NOTE: don't need to preserve the m2kqacache because we cannot provide it to the subsequent runs to resume. The qacache flag has been removed from the CLI.

This also allows for neat features like showing a diff of the folder structure between runs.
This architecture should support multiple pod restarts (even during planning/translation).

TODO: also need to figure out where to put the config files. Currently we are not accepting upload or use of config files.

workspace/
  myapp1/
    assets/
      expanded/
        source/
          lang-plat/
          estore/
          .m2kignore
        customizations/
          config-1/
          config-2/
        m2k.plan
      archives/
        source/
          lang-plat.zip
          estore.tar.gz
        customizations/
          config-1.zip
          config-2.zip
    artifacts/
      myapp1_12345/
        source/
          lang-plat/
          estore/
          .m2kignore
        customizations/
          config-1/
          config-2/
        output/
        output.zip
*/

// Verbose flag if set to true, will set logging level to debug level
var Verbose bool

// FileSystem implements the IApplication interface and manages the application data in a filesystem
type FileSystem struct {
}

// Download returns the app binary
func (a *FileSystem) Download() (file io.Reader, filename string) {
	path, err := exec.LookPath(appName)
	if err != nil {
		log.Warnf("Unable to find "+appName+" : %v", err)
		return nil, ""
	}
	f, err := os.Open(path)
	if err != nil {
		log.Errorf("failed to open the file at path %s . Error: %q", path, err)
		return nil, ""
	}
	return f, filepath.Base(path)
}

// NewApplication creates a new application in the filesystem
func (a *FileSystem) NewApplication(application Application) error {
	log.Infof("Creating application : %s", application.Name)
	if _, err := os.Stat(application.Name); !os.IsNotExist(err) {
		err := fmt.Errorf("the application %s already exists", application.Name)
		log.Error(err)
		return err
	}
	if err := os.MkdirAll(application.Name, defaultDirectoryPermissions); err != nil {
		log.Error(err)
		return err
	}
	return nil
}

// GetApplication returns the metadata about an application
func (a *FileSystem) GetApplication(name string) (Application, error) {
	app := Application{Name: name}
	_, err := os.Stat(name)
	if os.IsNotExist(err) {
		err := fmt.Errorf("the application %s does not exist", name)
		log.Error(err)
		return app, err
	}
	status := []ApplicationStatus{}
	//Checks for contents too if the dir exists
	if exists, _ := doesPathExist(filepath.Join(name, assetsDirectory)); exists {
		status = append(status, ApplicationStatusAssets)
	}
	if exists, _ := doesPathExist(filepath.Join(name, artifactsDirectory)); exists {
		status = append(status, ApplicationStatusArtifacts)
	}
	if exists, _ := doesPathExist(filepath.Join(name, assetsDirectory, expandedDirectory, "m2k.plan")); exists {
		status = append(status, ApplicationStatusPlan)
	}
	if exists, _ := doesPathExist(filepath.Join(name, m2kPlanOngoingFile+".*")); exists {
		status = append(status, ApplicationStatusPlanning)
	}
	app.Status = status
	log.Debugf("Application : %+v", app)
	return app, nil
}

// GetApplications returns the list of applications
func (a *FileSystem) GetApplications() []Application {
	applications := []Application{}
	files, err := ioutil.ReadDir("./")
	if err != nil {
		log.Debugf("Could not read applications.")
		return applications
	}

	for _, f := range files {
		if f.IsDir() && !strings.Contains(f.Name(), ".") && !strings.Contains(f.Name(), "+") {
			app, err := a.GetApplication(f.Name())
			if err == nil {
				applications = append(applications, app)
			}
		}
	}
	return applications
}

// DeleteApplication deletes an application from the filesysem
func (a *FileSystem) DeleteApplication(name string) error {
	return os.RemoveAll(name)
}

// UploadAsset uploads an asset into the filesystem
func (a *FileSystem) UploadAsset(appName string, filename string, file io.Reader, isCustomization bool) error {
	if _, err := a.GetApplication(appName); err != nil {
		return fmt.Errorf("failed to get the application with name %s . Error: %q", appName, err)
	}
	archiveName, expandedDirName, err := NormalizeAssetName(filename)
	if err != nil {
		return fmt.Errorf("failed to normalize the asset filename %s . Error: %q", filename, err)
	}

	assetsDir := filepath.Join(appName, assetsDirectory)
	archDir := filepath.Join(assetsDir, archivesDirectory, srcDirectory)
	if isCustomization {
		archDir = filepath.Join(assetsDir, archivesDirectory, customizationsDirectory)
	}
	srcDir := filepath.Join(assetsDir, expandedDirectory, srcDirectory)
	if isCustomization {
		srcDir = filepath.Join(assetsDir, expandedDirectory, customizationsDirectory)
	}

	archivePath := filepath.Join(archDir, archiveName)
	expandedDirPath := filepath.Join(srcDir, expandedDirName)

	if err := os.RemoveAll(expandedDirPath); err != nil {
		return fmt.Errorf("failed to remove the directory at path %s . Error: %q", expandedDirPath, err)
	}
	if err := os.MkdirAll(archDir, defaultDirectoryPermissions); err != nil {
		log.Error(err)
		return err
	}
	if err := putM2KIgnore(srcDir); err != nil { // also creates the directory if it doesn't exist, overwrites if it does exist
		log.Error(err)
		return err
	}
	if err := putM2KIgnore(expandedDirPath); err != nil { // TODO: is this necessary?
		log.Error(err)
		return err
	}

	// write the archive they uploaded
	f, err := os.OpenFile(archivePath, os.O_WRONLY|os.O_CREATE, defaultFilePermissions)
	if err != nil {
		log.Errorf("failed to write the file to path %s . Error: %q", archivePath, err)
		return err
	}
	defer f.Close()
	if _, err := io.Copy(f, file); err != nil {
		return fmt.Errorf("failed to receive the asset %s completely. Error: %q", filename, err)
	}

	// expand the archive
	if err := archiver.Unarchive(archivePath, expandedDirPath); err == nil {
		return nil
	}
	if filepath.Ext(archivePath) == ".zip" {
		if err := archiver.NewZip().Unarchive(archivePath, expandedDirPath); err != nil {
			log.Error(err)
			return err
		}
		return nil
	}
	if filepath.Ext(archivePath) == ".tar" {
		if err := archiver.NewTar().Unarchive(archivePath, expandedDirPath); err != nil {
			log.Error(err)
			return err
		}
		return nil
	}
	if filepath.Ext(archivePath) == ".tgz" || strings.HasSuffix(archivePath, ".tar.gz") {
		if err := archiver.NewTarGz().Unarchive(archivePath, expandedDirPath); err != nil {
			log.Error(err)
			return err
		}
		return nil
	}
	return fmt.Errorf("failed to expand the uploaded archive %s . Please use one of the supported formats %+v", filename, validArchiveExts)
}

// DeleteAsset deletes an application asset
func (a *FileSystem) DeleteAsset(appName string, asset string, isCustomization bool) error {
	archiveName, expandedDirName, err := NormalizeAssetName(asset)
	if err != nil {
		return fmt.Errorf("failed to normalize the asset filename %s . Error: %q", asset, err)
	}
	archivePath := filepath.Join(appName, assetsDirectory, archivesDirectory, srcDirectory, archiveName)
	if isCustomization {
		archivePath = filepath.Join(appName, assetsDirectory, archivesDirectory, customizationsDirectory, archiveName)
	}
	if _, err := os.Stat(archivePath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("the asset %s does not exist at path %s", asset, archivePath)
		}
		return fmt.Errorf("error occurred while tring to check if the asset %s exists at the path %s . Error: %q", asset, archivePath, err)
	}
	if err := os.Remove(archivePath); err != nil {
		log.Errorf("failed to delete the archive file at path %s . Error %q", archivePath, err)
		return err
	}
	expandedDirPath := filepath.Join(appName, assetsDirectory, expandedDirectory, srcDirectory, expandedDirName)
	if isCustomization {
		expandedDirPath = filepath.Join(appName, assetsDirectory, expandedDirectory, customizationsDirectory, expandedDirName)
	}
	if err := os.RemoveAll(expandedDirPath); err != nil {
		log.Errorf("failed to delete the directory at path %s . Error: %q", expandedDirPath, err)
		return err
	}
	return nil
}

// GetAsset returns an application asset
func (a *FileSystem) GetAsset(appName string, asset string, isCustomization bool) (file io.Reader, filename string, err error) {
	archiveName, _, err := NormalizeAssetName(asset)
	if err != nil {
		return nil, "", fmt.Errorf("failed to normalize the asset filename %s . Error: %q", asset, err)
	}
	archivePath := filepath.Join(appName, assetsDirectory, archivesDirectory, srcDirectory, archiveName)
	if isCustomization {
		archivePath = filepath.Join(appName, assetsDirectory, archivesDirectory, customizationsDirectory, archiveName)
	}
	if _, err := os.Stat(archivePath); err != nil {
		if os.IsNotExist(err) {
			return nil, "", fmt.Errorf("the asset %s does not exist at path %s", asset, archivePath)
		}
		return nil, "", fmt.Errorf("error occurred while tring to check if the asset %s exists at the path %s . Error: %q", asset, archivePath, err)
	}
	f, err := os.Open(archivePath)
	if err != nil {
		return nil, "", fmt.Errorf("failed to open the file at path %s . Error: %q", archivePath, err)
	}
	return f, filepath.Base(archivePath), nil
}

// GetAssetsList returns application asset list
func (a *FileSystem) GetAssetsList(appName string, isCustomization bool) (assets []string, err error) {
	archDir := filepath.Join(appName, assetsDirectory, archivesDirectory, srcDirectory)
	if isCustomization {
		archDir = filepath.Join(appName, assetsDirectory, archivesDirectory, customizationsDirectory)
	}
	files, err := ioutil.ReadDir(archDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read the directory at path %s containing the assets for the app %s . Error: %q", archDir, appName, err)
	}
	assets = []string{}
	for _, f := range files {
		assets = append(assets, f.Name())
	}
	return assets, nil
}

// GetSupportInfo returns information useful for debugging.
// Returns the output of move2kube version -l
func (*FileSystem) GetSupportInfo() map[string]string {
	cmd := exec.Command("move2kube", "version", "-l")
	cliVersionBytes, err := cmd.Output()
	if err != nil {
		log.Errorf("Failed to get the move2kube CLI version information. Error: %q", err)
		return nil
	}
	info := map[string]string{}
	info["cli_version"] = string(cliVersionBytes)
	info["api_version"] = version.GetVersion(true)
	info["platform"] = "unknown"
	if val, ok := os.LookupEnv("MOVE2KUBE_PLATFORM"); ok {
		info["platform"] = val
	}
	info["api_image"] = "unknown"
	if val, ok := os.LookupEnv("MOVE2KUBE_API_IMAGE_HASH"); ok {
		info["api_image"] = val
	}
	info["ui_image"] = "unknown"
	if val, ok := os.LookupEnv("MOVE2KUBE_UI_IMAGE_HASH"); ok {
		info["ui_image"] = val
	}
	info["docker"] = ("docker socket is mounted")
	if _, err := os.Stat("/var/run/docker.sock"); err != nil {
		if os.IsNotExist(err) {
			info["docker"] = "docker socket is not mounted"
		} else {
			info["docker"] = fmt.Sprintf("docker socket error: %q", err)
		}
	}
	return info
}

// GeneratePlan starts generation of plan of an application
func (a *FileSystem) GeneratePlan(appName string, debugMode bool) error {
	log.Infof("About to start planning application %s", appName)
	go runPlan(appName, debugMode)
	log.Infof("Planning started for application %s", appName)
	return nil
}

func runPlan(appName string, debugMode bool) bool {
	log.Infof("Starting plan for %s", appName)

	planid := strconv.Itoa(rand.Intn(100))
	m2kplanongoing := filepath.Join(appName, m2kPlanOngoingFile+"."+planid)
	emptyFile, err := os.Create(m2kplanongoing)
	if err != nil {
		log.Warn(err)
	}
	emptyFile.Close()

	srcDirectoryPath := filepath.Join(assetsDirectory, srcDirectory)
	var cmd *exec.Cmd

	if Verbose || debugMode {
		cmd = exec.Command("move2kube", "plan", "--verbose", "-s", srcDirectoryPath, "-n", appName)
	} else {
		cmd = exec.Command("move2kube", "plan", "-s", srcDirectoryPath, "-n", appName)
	}
	cmd.Dir = appName

	var wg sync.WaitGroup

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Errorf("RunCommand: cmd.StdoutPipe(): %v", err)
		return false
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		log.Errorf("RunCommand: cmd.StderrPipe(): %v", err)
		return false
	}

	if err := cmd.Start(); err != nil {
		log.Errorf("RunCommand: cmd.Start(): %v", err)
		return false
	}

	outch := make(chan string, 10)

	scannerStdout := bufio.NewScanner(stdout)
	scannerStdout.Split(bufio.ScanLines)
	wg.Add(1)
	go func() {
		for scannerStdout.Scan() {
			text := scannerStdout.Text()
			var re = regexp.MustCompile(timestampRegex)
			replacementString := "App name: " + appName + ";"
			updatedText := re.ReplaceAllString(text, replacementString)
			if strings.TrimSpace(text) != "" {
				outch <- updatedText
			}
		}
		wg.Done()
	}()
	scannerStderr := bufio.NewScanner(stderr)
	scannerStderr.Split(bufio.ScanLines)
	wg.Add(1)
	go func() {
		for scannerStderr.Scan() {
			text := scannerStderr.Text()
			var re = regexp.MustCompile(timestampRegex)
			replacementString := "App name: " + appName + ";"
			updatedText := re.ReplaceAllString(text, replacementString)
			if strings.TrimSpace(text) != "" {
				outch <- updatedText
			}
		}
		wg.Done()
	}()

	go func() {
		wg.Wait()
		close(outch)
	}()

	for t := range outch {
		if Verbose {
			generateVerboseLogs(t)
		} else {
			log.Info(t)
		}
	}
	os.Remove(m2kplanongoing)
	return true
}

// UpdatePlan updates the plan file for an application
func (a *FileSystem) UpdatePlan(appName string, plan string) error {
	log.Infof("Updating plan of %s", appName)
	planfilepath := filepath.Join(appName, m2kplanfilename)
	os.Remove(planfilepath)
	err := ioutil.WriteFile(planfilepath, []byte(plan), defaultFilePermissions)
	if err != nil {
		log.Errorf("Cannot open file to write : %s", err)
		return err
	}
	log.Infof("Plan updated successfully")
	return nil
}

// GetPlan returns the plan for an application
func (a *FileSystem) GetPlan(appName string) (file io.Reader, filename string) {
	log.Debugf("Fetching plan of %s", appName)
	planfilepath := filepath.Join(appName, m2kplanfilename)
	f, err := os.Open(planfilepath)
	if err != nil {
		log.Debugf("Cannot get file: %s", err)
		return nil, ""
	}
	return f, m2kplanfilename
}

// DeletePlan deletes plan for an application
func (a *FileSystem) DeletePlan(appName string) error {
	planfilepath := filepath.Join(appName, m2kplanfilename)
	if err := os.Remove(planfilepath); err != nil {
		log.Errorf("Cannot delete file: %s", err)
		return err
	}
	log.Infof("Plan deleted successfully")
	return nil
}

// Transform starts the transformation phase for an application
func (a *FileSystem) Transform(appName, artifactName, plan string, debugMode bool) error {
	log.Infof("About to start transformation of application %s", appName)

	artifactpath := filepath.Join(appName, artifactsDirectory, artifactName)
	err := os.MkdirAll(artifactpath, defaultDirectoryPermissions)
	if err != nil {
		log.Error(err)
		return err
	}
	if plan != "" {
		plan = strings.Replace(plan, "rootDir: assets/src/", "rootDir: ../../assets/src/", 1)
		planfilepath := filepath.Join(artifactpath, m2kplanfilename)
		if err := ioutil.WriteFile(planfilepath, []byte(plan), defaultFilePermissions); err != nil {
			log.Errorf("failed to write the plan file at path %s . Error: %q", planfilepath, err)
			return err
		}
	}

	artifactfilepath := filepath.Join(appName, artifactsDirectory, artifactName, appName+".zip")
	if _, err := os.Stat(artifactfilepath); !os.IsNotExist(err) {
		return nil
	}

	m2kqaservermetadatapath := filepath.Join(appName, artifactsDirectory, artifactName, m2kQAServerMetadataFile)
	if _, err := os.Stat(m2kqaservermetadatapath); !os.IsNotExist(err) {
		metadatayaml := types.AppMetadata{}
		err = ReadYaml(m2kqaservermetadatapath, &metadatayaml)
		if err != nil || metadatayaml.Node != getDNSHostName() {
			return nil
		}
		if !debugMode {
			if metadatayaml.Debug == "true" {
				debugMode = true
			}
		}
	}

	log.Infof("Debug level: %t", debugMode)
	transformch := make(chan string, 10)
	go runTransform(appName, artifactpath, artifactName, transformch, debugMode)
	log.Infof("Waiting for QA engine to start for app %s", appName)
	port := <-transformch
	appmetadata := types.AppMetadata{}
	appmetadata.URL = "http://localhost:" + port
	appmetadata.Node = getDNSHostName()
	appmetadata.Debug = strconv.FormatBool(debugMode)
	if appmetadata.Node == "" {
		appmetadata.Node = "localhost"
	}
	log.Infof("Setting hostname as %s", appmetadata.Node)
	log.Infof("QA engine to started for app %s at %s", appName, appmetadata.URL)

	err = WriteYaml(m2kqaservermetadatapath, appmetadata)
	if err != nil {
		log.Errorf("Cannot open file to write : %s", err)
		return err
	}

	log.Infof("Transformation started for application %s with url %s", appName, appmetadata.URL)
	return nil
}

func runTransform(appName string, artifactpath string, artifactName string, transformch chan string, debugMode bool) bool {
	log.Infof("Starting Transform for %s", appName)

	portint, err := freeport.GetFreePort()
	port := strconv.Itoa(portint)
	if err != nil {
		log.Warnf("Unable to get a free port : %s", err)
	}
	customizationsDirPath := filepath.Join(appName, assetsDirectory, customizationsDirectory)
	var cmd *exec.Cmd
	if Verbose || debugMode {
		cmd = exec.Command("move2kube", "transform", "--qadisablecli", "--customizations="+customizationsDirPath, "--verbose", "--qaport="+port, "--config="+filepath.Join(artifactpath, "m2kconfig.yaml"), "--source=../../assets/src/")
	} else {
		cmd = exec.Command("move2kube", "transform", "--qadisablecli", "--customizations="+customizationsDirPath, "--qaport="+port, "--config="+filepath.Join(artifactpath, "m2kconfig.yaml"), "--source=../../assets/src/")
	}
	cmd.Dir = artifactpath

	var wg sync.WaitGroup
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Errorf("RunCommand: cmd.StdoutPipe(): %v", err)
		return false
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		log.Errorf("RunCommand: cmd.StderrPipe(): %v", err)
		return false
	}
	if err := cmd.Start(); err != nil {
		log.Errorf("RunCommand: cmd.Start(): %v", err)
		return false
	}

	outch := make(chan string, 10)
	scannerStdout := bufio.NewScanner(stdout)
	scannerStdout.Split(bufio.ScanLines)
	wg.Add(1)
	go func() {
		for scannerStdout.Scan() {
			text := scannerStdout.Text()
			var re = regexp.MustCompile(timestampRegex)
			replacementString := "App name: " + appName + "; Artifact name:" + artifactName + ";"
			updatedText := re.ReplaceAllString(text, replacementString)
			if strings.TrimSpace(text) != "" {
				outch <- updatedText
			}
		}
		wg.Done()
	}()
	scannerStderr := bufio.NewScanner(stderr)
	scannerStderr.Split(bufio.ScanLines)
	wg.Add(1)
	go func() {
		for scannerStderr.Scan() {
			text := scannerStderr.Text()
			var re = regexp.MustCompile(timestampRegex)
			replacementString := "App name: " + appName + "; Artifact name:" + artifactName + ";"
			updatedText := re.ReplaceAllString(text, replacementString)
			if strings.TrimSpace(text) != "" {
				outch <- updatedText
			}
		}
		wg.Done()
	}()

	go func() {
		wg.Wait()
		close(outch)
		m2kqaservermetadatapath := filepath.Join(artifactpath, m2kQAServerMetadataFile)
		if err := os.RemoveAll(m2kqaservermetadatapath); err != nil {
			log.Errorf("Failed to remove the metadata directory at path %s . Error: %q", m2kqaservermetadatapath, err)
		}
		artifacts := filepath.Join(artifactpath, appName)
		zipPath := artifacts + ".zip"
		if err := archiver.NewZip().Archive([]string{artifacts}, zipPath); err != nil {
			log.Errorf("Failed to create the output zip file at path %s . Error: %q", zipPath, err)
		}
	}()

	for t := range outch {
		if strings.Contains(t, port) {
			transformch <- port
			close(transformch)
		}
		if Verbose {
			generateVerboseLogs(t)
		} else {
			log.Info(t)
		}
	}
	return true
}

// generateVerboseLogs synchronizes move2kube-api loggging level wrt move2kube logging level
func generateVerboseLogs(message string) {
	var loggingLevel string
	var re = regexp.MustCompile(loglevelRegex)
	sm := re.FindStringSubmatch(message)
	if len(sm) > 1 {
		loggingLevel = sm[1]
	} else {
		loggingLevel = "info"
	}
	syncLoggingLevel(loggingLevel, message)
}

// GetTargetArtifacts returns the target artifacts for an application
func (a *FileSystem) GetTargetArtifacts(appName string, artifact string) (file io.Reader, filename string) {
	artifactpath := filepath.Join(appName, artifactsDirectory, artifact, appName+".zip")
	m2kqaservermetadatapath := filepath.Join(appName, artifactsDirectory, artifact, m2kQAServerMetadataFile)
	f, err := os.Open(artifactpath)
	if err != nil {
		log.Error(err)
		if _, err := os.Stat(m2kqaservermetadatapath); os.IsNotExist(err) {
			return nil, "error"
		}
		return nil, "ongoing"
	}
	return f, filepath.Base(artifactpath)
}

// GetTargetArtifactsList returns the list of target artifacts for an application
func (a *FileSystem) GetTargetArtifactsList(appName string) (artifacts []string) {
	artifacts = []string{}
	files, err := ioutil.ReadDir(filepath.Join(appName, artifactsDirectory))
	if err != nil {
		log.Debug("Could not read applications.")
		return artifacts
	}

	for _, f := range files {
		if f.IsDir() && !strings.Contains(f.Name(), ".") {
			artifacts = append(artifacts, filepath.Base(f.Name()))
		}
	}
	return artifacts
}

// DeleteTargetArtifacts deletes target artifacts of an application
func (a *FileSystem) DeleteTargetArtifacts(appName string, artifacts string) error {
	err := os.RemoveAll(filepath.Join(appName, artifactsDirectory, artifacts))
	if err != nil {
		log.Errorf("Cannot delete file: %s", err)
		return err
	}
	return nil
}

// GetQuestion returns the current question for application which is in transformation phase
func (a *FileSystem) GetQuestion(appName string, artifact string) (problem string, err error) {
	log.Infof("Getting question %s for %s", appName, artifact)
	artifactpath := filepath.Join(appName, artifactsDirectory, artifact)
	m2kqaservermetadatapath := filepath.Join(artifactpath, m2kQAServerMetadataFile)
	metadatayaml := types.AppMetadata{}
	err = ReadYaml(m2kqaservermetadatapath, &metadatayaml)
	//TODO: Find a better way to orchestrate
	if err != nil {
		log.Infof("Artifact generation over for %s for %s", appName, artifact)
		log.Info(err)
		return "", err
	}
	hostname := getDNSHostName()
	if hostname == metadatayaml.Node {
		urlstr := metadatayaml.URL + "/problems/current"
		log.Infof("Getting question from %s", urlstr)
		resp, err := http.Get(urlstr)
		if err != nil {
			log.Error(err)
			return "", err
		}
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Error(err)
			return "", err
		}
		log.Infof(string(body))
		return string(body), nil
	}
	urlstr := "http://" + metadatayaml.Node + ":" + strconv.Itoa(apiServerPort) + "/api/v1/applications/" + appName + "/targetartifacts/" + artifact + "/problems/current"
	log.Infof("Getting question from %s", urlstr)
	resp, err := http.Get(urlstr)
	if err != nil {
		log.Error(err)
		return "", err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Error(err)
		return "", err
	}
	log.Infof("Question : %s", string(body))
	return string(body), nil
}

// PostSolution posts the solution for the current question
func (a *FileSystem) PostSolution(appName string, artifact string, solution string) error {
	artifactpath := filepath.Join(appName, artifactsDirectory, artifact)
	m2kqaservermetadatapath := filepath.Join(artifactpath, m2kQAServerMetadataFile)
	metadatayaml := types.AppMetadata{}
	err := ReadYaml(m2kqaservermetadatapath, &metadatayaml)
	if err != nil {
		return nil
	}
	hostname := getDNSHostName()
	if hostname == metadatayaml.Node {
		log.Infof("Answer : %s", solution)
		urlstr := metadatayaml.URL + "/problems/current/solution"
		resp, err := http.Post(urlstr, "application/json", bytes.NewBuffer([]byte(solution)))
		if err != nil {
			log.Error(err)
			return err
		}
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Error(err)
			return err
		}
		if string(body) != "" {
			log.Infof(string(body))
		}
		return nil
	}
	urlstr := "http://" + metadatayaml.Node + ":" + strconv.Itoa(apiServerPort) + "/api/v1/applications/" + appName + "/targetartifacts/" + artifact + "/problems/current/solution"
	resp, err := http.Post(urlstr, "application/json", bytes.NewBuffer([]byte(solution)))
	if err != nil {
		log.Error(err)
		return err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Error(err)
		return err
	}
	log.Infof(string(body))
	return nil

}

// NewFileSystem returns a new IApplication object which manages an application in a filesystem
func NewFileSystem() *FileSystem {
	fileSystem := &FileSystem{}
	applications := fileSystem.GetApplications()
	for _, application := range applications {
		artifacts := fileSystem.GetTargetArtifactsList(application.Name)
		for _, artifact := range artifacts {
			err := fileSystem.Transform(application.Name, artifact, "", false)
			if err != nil {
				log.Errorf("Error while starting transform : %s", err)
			}
		}
		m2kplanongoing := filepath.Join(application.Name, m2kPlanOngoingFile+".*")
		files, err := filepath.Glob(m2kplanongoing)
		if err != nil {
			log.Warn(err)
		} else {
			for _, f := range files {
				if err := os.Remove(f); err != nil {
					log.Warn(err)
				}
			}
		}
	}
	return fileSystem
}

func doesPathExist(path string) (bool, error) {
	if strings.HasSuffix(path, ".*") {
		files, err := filepath.Glob(path)
		if err != nil {
			log.Debugf("Cannot get files : %s", err)
			return false, nil
		}
		log.Debugf("Got files : %s", files)
		if len(files) > 0 {
			return true, nil
		}
		return false, nil
	}
	fileinfo, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false, nil
	} else if err != nil {
		return false, err
	} else {
		if fileinfo.IsDir() {
			f, err := os.Open(path)
			if err != nil {
				return false, nil
			}
			defer f.Close()
			_, err = f.Readdirnames(1) // Or f.Readdir(1)
			if err == io.EOF {
				return false, nil
			}
			return true, nil
		}
		return true, nil
	}
}

// WriteYaml writes an yaml to disk
func WriteYaml(outputPath string, data interface{}) error {
	var b bytes.Buffer
	encoder := yaml.NewEncoder(&b)
	encoder.SetIndent(2)
	if err := encoder.Encode(data); err != nil {
		log.Error("Error while Encoding object")
		return err
	}
	err := ioutil.WriteFile(outputPath, b.Bytes(), 0666)
	if err != nil {
		log.Errorf("Error writing yaml to file: %s", err)
		return err
	}
	return nil
}

// ReadYaml reads an yaml into an object
func ReadYaml(file string, data interface{}) error {
	yamlFile, err := ioutil.ReadFile(file)
	if err != nil {
		log.Debugf("Error in reading yaml file %s: %s.", file, err)
		return err
	}
	err = yaml.Unmarshal(yamlFile, data)
	if err != nil {
		log.Debugf("Error in unmarshalling yaml file %s: %s.", file, err)
		return err
	}
	return nil
}

func getDNSHostName() string {
	dnsHostName := ""
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Debugf("%s", err)
		return ""
	}

	// handle err
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			log.Debugf("%s", err)
		}

		// handle err
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			ptr, _ := net.LookupAddr(ip.String())
			for _, ptrvalue := range ptr {
				log.Debugf("HostNames : %s", ptrvalue)
				if len(dnsHostName) <= len(ptrvalue) {
					dnsHostName = ptrvalue
				}
			}
		}
	}
	log.Debugf("Chosen hostname : %s", dnsHostName)
	return dnsHostName
}

//syncLoggingLevel matches log levels of Move2Kube-api and Move2Kube
func syncLoggingLevel(loggingLevel, message string) {
	switch {
	case loggingLevel == "debug":
		log.Debug(message)
	case loggingLevel == "info":
		log.Info(message)
	case loggingLevel == "error":
		log.Error(message)
	case loggingLevel == "warning":
		log.Warn(message)
	case loggingLevel == "panic":
		log.Error(message)
	case loggingLevel == "fatal":
		log.Error(message)
	default:
		log.Info(message)
	}
}

// putM2KIgnore writes a .m2kignore file to a directory that ignores the contents of that directory.
// NOTE: It will not ignore subdirectories. if the directory does not exist it will be created.
func putM2KIgnore(path string) error {
	if err := os.MkdirAll(path, defaultDirectoryPermissions); err != nil {
		return fmt.Errorf("failed to create a directory at the path %s . Error: %q", path, err)
	}
	m2kIgnorePath := filepath.Join(path, ".m2kignore")
	if err := ioutil.WriteFile(m2kIgnorePath, []byte("."), defaultFilePermissions); err != nil {
		return fmt.Errorf("failed to write a .m2kingore file to the path %s . Error: %q", m2kIgnorePath, err)
	}
	return nil
}

// MakeFileNameCompliant returns a DNS-1123 standard string
// Motivated by https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#syntax-and-character-set
// Also see page 1 "ASSUMPTIONS" heading of https://tools.ietf.org/html/rfc952
// Also see page 13 of https://tools.ietf.org/html/rfc1123#page-13
func MakeFileNameCompliant(name string) string {
	if len(name) == 0 {
		log.Error("The input name is empty.")
		return ""
	}
	baseName := filepath.Base(name)
	invalidChars := regexp.MustCompile("[^a-zA-Z0-9-.]+")
	processedName := invalidChars.ReplaceAllLiteralString(baseName, "-")
	if len(processedName) > 63 {
		log.Debugf("Warning: The processed name %q is longer than 63 characters long.", processedName)
	}
	first := processedName[0]
	last := processedName[len(processedName)-1]
	if first == '-' || first == '.' || last == '-' || last == '.' {
		log.Debugf("Warning: The first and/or last characters of the name %q are not alphanumeric.", processedName)
	}
	return processedName
}

// NormalizeAssetName normalizes the asset filename removing invalid characters, etc.
// It also returns the filename without the extension so it can be used as the name for the directory after expansion.
func NormalizeAssetName(filename string) (archiveName string, expandedDirName string, err error) {
	assetName := filepath.Base(filepath.Clean(filename))
	if assetName == "." || assetName == string(os.PathSeparator) {
		return "", "", fmt.Errorf("the asset filename `%s` is invalid", filename)
	}
	assetName = MakeFileNameCompliant(assetName)
	ext := filepath.Ext(assetName)
	if !IsStringPresent(validArchiveExts, ext) || (ext == ".gz" && !strings.HasSuffix(assetName, ".tar.gz")) {
		return "", "", fmt.Errorf("the archive format %s is not supported. Please use one of %+v when uploading", ext, validArchiveExts)
	}
	if ext == ".gz" {
		base := strings.TrimSuffix(assetName, ".tar.gz")
		return assetName, base, nil
	}
	base := strings.TrimSuffix(assetName, ext)
	return assetName, base, nil
}

// IsStringPresent checks if a value is present in a slice
func IsStringPresent(list []string, value string) bool {
	for _, val := range list {
		if strings.EqualFold(val, value) {
			return true
		}
	}
	return false
}
