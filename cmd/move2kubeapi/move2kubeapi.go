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
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/konveyor/move2kube-api/internal/application"
	"github.com/konveyor/move2kube-api/internal/move2kubeapi"
)

var (
	workspace string
	port      int
)

func main() {
	// Setup
	viper.AutomaticEnv()

	apiCmd := &cobra.Command{
		Use:   "move2kube-api",
		Short: "Move2Kube API starts the api server which manages the application data in a filesystem.",
		Long: `Move2Kube API starts the api server which manages the application data in a filesystem.

For more information, visit https://move2kube.konveyor.io/
`,
		Run: func(cmd *cobra.Command, _ []string) {
			if application.Verbose {
				log.SetLevel(log.DebugLevel)
			}
			log.Debugf("Verbose output: %v", application.Verbose)
			move2kubeapi.Serve(port)
		},
	}

	apiCmd.Flags().BoolVarP(&application.Verbose, "verbose", "v", false, "Enable verbose output")
	apiCmd.Flags().IntVarP(&port, "port", "p", 8080, "Port for the QA service. By default it chooses a random free port.")

	apiCmd.AddCommand(getVersionCommand())

	if err := apiCmd.Execute(); err != nil {
		log.Fatalf("Error: %q", err)
	}
}
