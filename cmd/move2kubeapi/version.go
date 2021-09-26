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
	"fmt"

	"github.com/konveyor/move2kube-api/cmd/version"
	"github.com/konveyor/move2kube-api/internal/common"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func getVersionCommand() *cobra.Command {
	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print the version information",
		Long:  "Print the version information",
		Run:   func(*cobra.Command, []string) { fmt.Println(version.GetVersion(common.Config.VersionLong)) },
	}
	versionCmd.Flags().BoolP("long", "l", false, "print the version details")
	viper.BindPFlag("version-long", versionCmd.Flags().Lookup("long"))
	return versionCmd
}
