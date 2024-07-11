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

package filesystem

import (
	"io"

	"github.com/konveyor/move2kube-api/internal/types"
)

// IFileSystem defines an interface that can manage Move2Kube workspaces and projects
type IFileSystem interface {
	GetSupportInfo() map[string]string
	Download() (file io.Reader, filename string, err error)
	ListWorkspaceIds() ([]string, error)
	ListWorkspaces(workspaceIds []string) ([]types.Workspace, error)
	CreateWorkspace(workspace types.Workspace) error
	ReadWorkspace(workspaceId string) (types.Workspace, error)
	UpdateWorkspace(workspace types.Workspace) error
	DeleteWorkspace(workspaceId string) error
	ListProjects(workspaceId string) ([]types.Project, error)
	CreateProject(workspaceId string, project types.Project) error
	ReadProject(workspaceId, projectId string) (types.Project, error)
	UpdateProject(workspaceId string, project types.Project) error
	DeleteProject(workspaceId, projectId string) error
	CreateProjectInput(workspaceId, projectId string, projInput types.ProjectInput, file io.Reader, isCommon bool) error
	ReadProjectInput(workspaceId, projectId, projInputId string, isCommon bool) (projInput types.ProjectInput, file io.Reader, err error)
	DeleteProjectInput(workspaceId, projectId, projInputId string, isCommon bool) error
	StartPlanning(workspaceId, projectId, remoteSource string, debugMode bool, dumpCliLogs bool) error
	ReadPlan(workspaceId, projectId string) (plan io.Reader, err error)
	UpdatePlan(workspaceId, projectId string, plan io.Reader) error
	DeletePlan(workspaceId, projectId string) error
	StartTransformation(workspaceId, projectId string, projOutput types.ProjectOutput, plan io.Reader, debugMode, skipQA bool, dumpCliLogs bool) error
	ResumeTransformation(workspaceId, projectId, projOutputId string, debugMode, skipQA bool) error
	ReadProjectOutput(workspaceId, projectId, projOutputId string) (projOutput types.ProjectOutput, file io.Reader, err error)
	ReadProjectOutputGraph(workspaceId, projectId, projOutputId string) (projOutput types.ProjectOutput, file io.Reader, err error)
	DeleteProjectOutput(workspaceId, projectId, projOutputId string) error
	GetQuestion(workspaceId, projectId, projOutputId string) (problem string, err error)
	PostSolution(workspaceId, projectId, projOutputId, solution string) error
}
