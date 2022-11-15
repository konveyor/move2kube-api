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
	"log"
	"strings"

	"github.com/konveyor/move2kube-api/cmd/main/umask"
	"github.com/konveyor/move2kube-api/internal/common"
	"github.com/konveyor/move2kube-api/internal/move2kubeapi"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func getRootCommand() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "move2kube-api",
		Short: "Move2Kube API starts the api server which manages the project data in a filesystem.",
		Long: `Move2Kube API starts the api server which manages the project data in a filesystem.
This server can also be configured using environment variables and/or a config file.
The order of precedence for reading configuration is:
command line flag > environment variable > config file > default value
The environment variable name is just the flag name capitalized, prefixed with "M2K" and all hyphens replaced with underscores.
Example:
	M2K_PORT=8080 M2K_SECURE_COOKIES=true M2K_STATIC_FILES_DIR='path/to/dist' move2kube-api --log-level trace

For more information, visit https://move2kube.konveyor.io/`,
		Args: cobra.NoArgs,
		Run: func(*cobra.Command, []string) {
			if err := move2kubeapi.Serve(); err != nil {
				logrus.Fatal(err)
			}
		},
	}
	app := common.APP_NAME_SHORT
	rootCmd.PersistentFlags().StringP("config", "c", "", "Path to the config file.")
	rootCmd.PersistentFlags().String("log-level", logrus.InfoLevel.String(), `Set the logging level. Options are: ["panic", "fatal", "error", "warn", "info", "debug", "trace"]`)
	rootCmd.Flags().IntP("port", "p", 8080, "Port to listen on.")
	rootCmd.Flags().Int("cookie-max-age", 2*3600, "Max age for session cookies (in seconds).")
	rootCmd.Flags().Int("max-upload-size", 100*1024*1024, "Max size (in bytes) for file uploads.")
	rootCmd.Flags().Int("plan-timeout-seconds", -1, "No. of seconds to wait before cancelling ongoing plan generation. Negative value means no timeout.")
	rootCmd.Flags().Int("transform-timeout-seconds", -1, "No. of seconds to wait before cancelling ongoing transformation. Negative value means no timeout.")
	rootCmd.Flags().Bool("auth-enabled", false, "Enable authentication and authorization.")
	rootCmd.Flags().Bool("secure-cookies", false, "Send cookies only if it is a https TLS connection. Turn this on in production environments.")
	rootCmd.Flags().Bool("clean-up-after-transform", false, "Delete extra files after a transformation is finished. Helps save storage space.")
	rootCmd.Flags().Bool("enable-local-execution", false, "Enable local execution.")
	rootCmd.Flags().String("data-dir", "data", "Path to the directory where all the data will stored. It will be created if it doesn't exist.")
	rootCmd.Flags().String("static-files-dir", "", "Path to the directory containing static files to be served. Used to serve the Move2Kube UI.")
	rootCmd.Flags().String("session-secret", "", "A random secret to use for signing session cookies. By default it generates a new session secret.")
	rootCmd.Flags().String("current-host", "http://localhost:8080", "URL where this server is deployed.")
	rootCmd.Flags().String("auth-server", "http://localhost:8081", "URL of the authorization server.")
	rootCmd.Flags().String("auth-server-base-path", "/auth-server", "If the authorization server is hosted under a sub path, specify it here.")
	rootCmd.Flags().String("auth-server-login-path", "", "If the authorization server has a different login path, specify it here.")
	rootCmd.Flags().Int("auth-server-timeout", 3*60, "Timeout (in seconds) for all requests sent to the auth server. Default is 3 minutes.")
	rootCmd.Flags().String("auth-server-realm", "m2krealm", "The realm configured in the authorization server.")
	rootCmd.Flags().String("oidc-discovery-endpoint-path", "", "The OIDC discovery endpoint path for the authorization server. If not specified it uses the default for Keycloak.")
	rootCmd.Flags().String("uma-configuration-endpoint-path", "", "The UMA configuration endpoint path for the authorization server. If not specified it uses the default for Keycloak.")
	rootCmd.Flags().String(app+"-client-client-id", app+"-client", "The OAuth 2.0 client id for the client side.")
	rootCmd.Flags().String(app+"-client-client-secret", "af10bd64-03e6-47cc-8733-4d04354cf625", "The OAuth 2.0 client secret for the client side.")
	rootCmd.Flags().String(app+"-client-id-not-client-id", "fb0411ca-3637-4925-9325-9f979bb0e826", "The Id of the client on the Keycloak server. This is NOT the client Id used by OAuth 2.0.")
	rootCmd.Flags().String(app+"-server-client-id", app+"-server", "The OAuth 2.0 client id for the server side.")
	rootCmd.Flags().String(app+"-server-client-secret", "8a1340ff-de5d-42a0-8b40-b6239c7cfc58", "The OAuth 2.0 client secret for the server side.")
	rootCmd.Flags().String("default-resource-id", "b4d9b0fd-ffdb-4533-9536-5c315af07352", "Resource id on the Keycloak server.")
	rootCmd.Flags().String("host", "localhost", "The host name of the server.")
	rootCmd.Flags().String("https-cert", "", "The path to the certificate file for HTTPS.")
	rootCmd.Flags().String("https-key", "", "The path to the private key file for HTTPS. Must be an unencrypted private key file")
	// CloudEvents
	rootCmd.Flags().Bool("cloud-events-enabled", false, "Enable CloudEvents reporting.")
	rootCmd.Flags().String("cloud-events-endpoint", "", "Endpoint where CloudEvents are reported.")
	rootCmd.Flags().String("cloud-events-access-token", "", "Access token to use when reporting CloudEvents.")
	rootCmd.Flags().String("cloud-events-spec-version", "1.0", "Version of the CloudEvents spec.")
	rootCmd.Flags().String("cloud-events-type", "", "Type of the CloudEvents event.")
	rootCmd.Flags().String("cloud-events-subject", "move2kube-api", "Subject to use when reporting CloudEvents.")

	viper.BindPFlags(rootCmd.PersistentFlags())
	viper.BindPFlags(rootCmd.Flags())
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	return rootCmd
}

func readConfigFile() {
	viper.SetConfigType("yaml")
	if !viper.IsSet("config") {
		return
	}
	configFilePath := viper.GetString("config")
	logrus.Infof("reading config from file at path %s", configFilePath)
	viper.SetConfigFile(configFilePath)
	if err := viper.ReadInConfig(); err != nil {
		logrus.Fatalf("failed to read the config file at path %s . Error: %q", configFilePath, err)
	}
}

func setupViper() {
	viper.SetEnvPrefix(strings.ToUpper(common.APP_NAME_SHORT))
	viper.AutomaticEnv()
	readConfigFile()
	if err := viper.Unmarshal(&common.Config); err != nil {
		logrus.Fatalf("failed to unmarshal the config. Error: %q", err)
	}
}

func onInitialize() {
	setupViper()
	logLevel, err := logrus.ParseLevel(common.Config.LogLevel)
	if err != nil {
		log.Fatalf("the log level is invalid. Error: %q", err)
	}
	if common.Config.AuthServerTimeout <= 0 {
		log.Fatalf("the auth server timeout is invalid. Expected a positive integer. Actual: '%d'", common.Config.AuthServerTimeout)
	}
	logrus.SetLevel(logLevel)
	logrus.Debugf("log level: %s", logLevel.String())
	logrus.Debugf("using the following configuration:\n%s", common.Config.String())
}

func setupCobraAndRun() error {
	umask.SetUmask()
	rootCmd := getRootCommand()
	rootCmd.AddCommand(getVersionCommand())
	cobra.OnInitialize(onInitialize)
	return rootCmd.Execute()
}

func main() {
	if err := setupCobraAndRun(); err != nil {
		logrus.Fatal(err)
	}
}
