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
	assetsDirectory          = string(ApplicationStatusAssets)
	artifactsDirectoryName   = string(ApplicationStatusArtifacts)
	archivesDirectory        = "archives"
	srcDirectory             = "src"
	containersDirectory      = "containers"
	m2kplanfilename          = appNameShort + ".plan"
	m2kQAServerMetadataFile  = "." + appNameShort + "qa"
	m2kPlanOngoingFile       = "." + appNameShort + "plan"
	apiServerPort            = 8080
	timestampRegex           = `time="\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z"`
	loglevelRegex            = `level=([a-z]+) `
	newfilesMetadataFileName = "newfiles.txt"
)

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
		log.Errorf("Cannot get file: %s", err)
		return nil, ""
	}
	return f, filepath.Base(path)

}

// NewApplication creates a new application in the filesystem
func (a *FileSystem) NewApplication(application Application) error {
	log.Infof("Creating application : %s", application.Name)
	_, err := os.Stat(application.Name)
	if !os.IsNotExist(err) {
		log.Errorf("Application %s already exists.", application.Name)
		return fmt.Errorf("already exists")
	}

	err = os.MkdirAll(application.Name, 0777)
	if err != nil {
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
		log.Errorf("Application %s does not exist.", name)
		return app, fmt.Errorf("not found")
	}
	status := []ApplicationStatus{}
	//Checks for contents too if the dir exists
	if exists, _ := doesPathExist(filepath.Join(name, assetsDirectory)); exists {
		status = append(status, ApplicationStatusAssets)
	}
	if exists, _ := doesPathExist(filepath.Join(name, artifactsDirectoryName)); exists {
		status = append(status, ApplicationStatusArtifacts)
	}
	if exists, _ := doesPathExist(filepath.Join(name, "m2k.plan")); exists {
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
func (a *FileSystem) UploadAsset(appName string, filename string, file io.Reader) error {
	_, err := a.GetApplication(appName)
	if err != nil {
		log.Error("Application does not exist")
		return err
	}

	archivefilePath := filepath.Join(appName, assetsDirectory, archivesDirectory, filename)
	srcDirectoryPath := strings.Split(filepath.Join(appName, assetsDirectory, srcDirectory, filename), ".")[0]
	os.RemoveAll(srcDirectoryPath)
	err = os.MkdirAll(filepath.Join(appName, assetsDirectory, archivesDirectory), 0777)
	if err != nil {
		log.Error(err)
		return err
	}
	err = os.MkdirAll(srcDirectoryPath, 0777)
	if err != nil {
		log.Error(err)
		return err
	}

	err = ioutil.WriteFile(filepath.Join(appName, assetsDirectory, srcDirectory, ".m2kignore"), []byte("."), 0777)
	if err != nil {
		log.Error(err)
		return err
	}
	err = ioutil.WriteFile(filepath.Join(srcDirectoryPath, ".m2kignore"), []byte("."), 0777)
	if err != nil {
		log.Error(err)
		return err
	}

	f, err := os.OpenFile(archivefilePath, os.O_WRONLY|os.O_CREATE, 0777)
	if err != nil {
		log.Errorf("Cannot open file to write : %s", err)
		return err
	}
	defer f.Close()
	_, _ = io.Copy(f, file)
	err = archiver.Unarchive(archivefilePath, srcDirectoryPath)
	if err == nil {
		return nil
	} else if filepath.Ext(archivefilePath) == "zip" {
		err = archiver.NewZip().Unarchive(archivefilePath, srcDirectoryPath)
		if err == nil {
			return nil
		} else if filepath.Ext(archivefilePath) == "tar" {
			err = archiver.NewTar().Unarchive(archivefilePath, srcDirectoryPath)
			if err == nil {
				return nil
			} else if filepath.Ext(archivefilePath) == "tgz" || strings.HasSuffix(archivefilePath, "tar.gz") {
				err = archiver.NewTarGz().Unarchive(archivefilePath, srcDirectoryPath)
				if err == nil {
					return nil
				}
				log.Error(err)
				return err
			}
		}
	}
	return nil
}

// DeleteAsset deletes an application asset
func (a *FileSystem) DeleteAsset(appName string, asset string) error {
	files, err := filepath.Glob(filepath.Join(appName, assetsDirectory, archivesDirectory, asset) + ".*")
	if err != nil {
		log.Errorf("Cannot get files to delete : %s", err)
		return err
	}
	for _, f := range files {
		if err := os.Remove(f); err != nil {
			log.Errorf("Cannot delete file: %s", err)
			return err
		}
	}
	os.RemoveAll(filepath.Join(appName, assetsDirectory, srcDirectory, asset))
	if err != nil {
		log.Errorf("Cannot delete files : %s", err)
		return err
	}
	return nil
}

// GetAsset returns an application asset
func (a *FileSystem) GetAsset(appName string, asset string) (file io.Reader, filename string) {
	files, err := filepath.Glob(filepath.Join(appName, assetsDirectory, archivesDirectory, asset) + ".*")
	if err != nil || len(files) == 0 {
		log.Errorf("Cannot open file to write : %s", err)
		return nil, ""
	}
	f, err := os.Open(files[0])
	if err != nil {
		log.Errorf("Cannot get file: %s", err)
		return nil, ""
	}
	return f, filepath.Base(files[0])
}

// GetAssetsList returns application asset list
func (a *FileSystem) GetAssetsList(appName string) (assets []string) {
	assets = []string{}
	files, err := ioutil.ReadDir(filepath.Join(appName, assetsDirectory, srcDirectory))
	if err != nil {
		log.Debug("Could not read applications.")
		return assets
	}

	for _, f := range files {
		if f.IsDir() && !strings.Contains(f.Name(), ".") {
			assets = append(assets, filepath.Base(f.Name()))
		}
	}
	return assets
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
	err := ioutil.WriteFile(planfilepath, []byte(plan), 0777)
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

	artifactpath := filepath.Join(appName, artifactsDirectoryName, artifactName)
	err := os.MkdirAll(artifactpath, 0777)
	if err != nil {
		log.Error(err)
		return err
	}
	if plan != "" {
		plan = strings.Replace(plan, "rootDir: assets/src/", "rootDir: ../../assets/src/", 1)
		planfilepath := filepath.Join(artifactpath, m2kplanfilename)
		err := ioutil.WriteFile(planfilepath, []byte(plan), 0777)
		if err != nil {
			log.Errorf("Cannot open file to write : %s", err)
			return err
		}
	}

	artifactfilepath := filepath.Join(appName, artifactsDirectoryName, artifactName, appName+".zip")
	if _, err := os.Stat(artifactfilepath); !os.IsNotExist(err) {
		return nil
	}

	m2kqaservermetadatapath := filepath.Join(appName, artifactsDirectoryName, artifactName, m2kQAServerMetadataFile)
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
	var cmd *exec.Cmd
	if Verbose || debugMode {
		cmd = exec.Command("move2kube", "transform", "--qadisablecli", "--verbose", "--qaport="+port, "--config="+filepath.Join(artifactpath, "m2kconfig.yaml"), "--source=../../assets/src/")
	} else {
		cmd = exec.Command("move2kube", "transform", "--qadisablecli", "--qaport="+port, "--config="+filepath.Join(artifactpath, "m2kconfig.yaml"), "--source=../../assets/src/")
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
	artifactpath := filepath.Join(appName, artifactsDirectoryName, artifact, appName+".zip")
	m2kqaservermetadatapath := filepath.Join(appName, artifactsDirectoryName, artifact, m2kQAServerMetadataFile)
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
	files, err := ioutil.ReadDir(filepath.Join(appName, artifactsDirectoryName))
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
	err := os.RemoveAll(filepath.Join(appName, artifactsDirectoryName, artifacts))
	if err != nil {
		log.Errorf("Cannot delete file: %s", err)
		return err
	}
	return nil
}

// GetQuestion returns the current question for application which is in transformation phase
func (a *FileSystem) GetQuestion(appName string, artifact string) (problem string, err error) {
	log.Infof("Getting question %s for %s", appName, artifact)
	artifactpath := filepath.Join(appName, artifactsDirectoryName, artifact)
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
	artifactpath := filepath.Join(appName, artifactsDirectoryName, artifact)
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
func NewFileSystem() IApplication {
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
