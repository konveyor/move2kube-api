/*
Copyright IBM Corporation 2021

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

package cloudevents

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/konveyor/move2kube-api/internal/common"
	"github.com/konveyor/move2kube-api/internal/types"
)

const (
	// CLOUD_EVENT_USER_EMAIL is the one of the keys sent in the data section of a cloud event. It contains the email.
	CLOUD_EVENT_USER_EMAIL = "userEmail"
	// CLOUD_EVENT_TEAM_NAME is the one of the keys sent in the data section of a cloud event. It contains the workspace name.
	CLOUD_EVENT_TEAM_NAME = "teamName"
)

// SendCloudEvent is used to send an event according to the CloudEvents spec
func SendCloudEvent(urlPath string, data map[string]interface{}) error {
	// https://datatracker.ietf.org/doc/html/rfc3339#section-5.8
	timestamp, _, err := common.GetTimestamp()
	if err != nil {
		return fmt.Errorf("failed to get the timestamp. Error: %q", err)
	}
	event := types.CloudEvent{
		SpecVersion:     common.Config.CloudEventsSpecVersion,
		Type:            common.Config.CloudEventsType,
		Source:          urlPath,
		Id:              uuid.NewString(),
		Subject:         common.Config.CloudEventsSubject,
		Time:            timestamp,
		DataContentType: common.CONTENT_TYPE_JSON,
		Data:            data,
	}
	jsonBytes, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal the data to json. Error: %q", err)
	}
	eventEndpoint := common.Config.CloudEventsEndpoint
	req, err := http.NewRequest("PUT", eventEndpoint, bytes.NewBuffer(jsonBytes))
	if err != nil {
		return fmt.Errorf("failed to create a PUT request to the URL %s . Error: %q", eventEndpoint, err)
	}
	req.Header.Set(common.CONTENT_TYPE_HEADER, common.CONTENT_TYPE_CLOUD_EVENT)
	req.Header.Set("x-access-token", common.Config.CloudEventsAccessToken)
	resp, err := new(http.Client).Do(req)
	if err != nil {
		return fmt.Errorf("failed to send the POST request to the URL %s . Error: %q", eventEndpoint, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("got an error response code from cloud event. Status: %s", resp.Status)
	}
	return nil
}
