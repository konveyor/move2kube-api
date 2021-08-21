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

package sessions

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"math"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gorilla/sessions"
	"github.com/konveyor/move2kube-api/internal/authserver"
	"github.com/konveyor/move2kube-api/internal/common"
	"github.com/konveyor/move2kube-api/internal/types"
	"github.com/sirupsen/logrus"
)

// Session contains data for a user session
type Session struct {
	Id                    string         `json:"id"`
	Tokens                types.Tokens   `json:"tokens"`
	User                  types.UserInfo `json:"user"`
	PostLoginRedirectPath string         `json:"post_login_redirect_path"`
}

const (
	// USER_SESSION_NAME is the name of the cookie containing the user session id
	USER_SESSION_NAME = common.APP_NAME_SHORT + "-ui-user"
	// SESSION_KEY_SESSION_INFO is the key used to store the session struct in the session store
	SESSION_KEY_SESSION_INFO = "session-info"
)

var (
	sessionStore *sessions.FilesystemStore
)

// SetupSessionStore sets up the session store.
func SetupSessionStore() error {
	logrus.Trace("SetupSessionStore start")
	sessionsDir := filepath.Join(common.Config.DataDir, common.SESSIONS_DIR)
	if err := os.MkdirAll(sessionsDir, 0777); err != nil {
		return fmt.Errorf("failed to create the directory at path %s Error: %q", sessionsDir, err)
	}
	gob.Register(Session{}) // required for serializing to session store.
	sessionSecret := common.Config.SessionSecret
	if sessionSecret == "" {
		randomBytes := make([]byte, 32)
		if _, err := rand.Read(randomBytes); err != nil {
			return fmt.Errorf("failed to read some random bytes to create the session secret. Error: %q", err)
		}
		randomBytesHash := sha256.Sum256(randomBytes)
		sessionSecret = hex.EncodeToString(randomBytesHash[:])
	}
	sessionStore = sessions.NewFilesystemStore(sessionsDir, []byte(sessionSecret))
	if sessionStore == nil {
		return fmt.Errorf("failed to get a session store")
	}
	sessionStore.Options.HttpOnly = true
	sessionStore.Options.SameSite = http.SameSiteLaxMode // Strict mode causes issues when logging in via external identity provider.
	sessionStore.Options.Secure = common.Config.SecureCookies
	sessionStore.Options.MaxAge = common.Config.CookieMaxAge
	sessionStore.MaxLength(math.MaxInt16) // Required to prevent "securecookie: the value is too long" error. See https://github.com/markbates/goth/pull/141/files
	logrus.Trace("SetupSessionStore end")
	return nil
}

// RefreshUserTokensIfExpired refreshs the user token if it has expired
func (session *Session) RefreshUserTokensIfExpired() bool {
	logrus.Trace("RefreshUserTokensIfExpired start")
	logrus.Debugf("session.Tokens %+v", session.Tokens)
	if _, err := authserver.DecodeToken(session.Tokens.AccessToken); err == nil {
		logrus.Debug("user access token is still valid.")
		return true
	} else if _, ok := err.(types.ErrorTokenExpired); ok {
		logrus.Debugf("user access token expired: %q . refreshing...", err)
	} else {
		logrus.Debugf("failed to decode the user access token. Error: %q", err)
	}
	if _, err := authserver.DecodeToken(session.Tokens.RefreshToken); err != nil {
		logrus.Errorf("failed to decode the refresh token. Error: %q", err)
		if _, ok := err.(types.ErrorTokenExpired); ok {
			logrus.Debugf("user refresh token also expired: %q . Please login again.", err)
			return false
		}
		logrus.Debugf("trying to use the refresh token anyway...")
	}
	var err error
	session.Tokens, err = common.GetTokenUsingRefreshToken(common.Config.OIDCInfo.TokenEndpoint, session.Tokens.RefreshToken, common.Config.M2kClientBasicAuth())
	if err != nil {
		logrus.Errorf("failed to get a new user access token with the user refresh token. Error: %q", err)
		return false
	}
	logrus.Debug("got a new user access token using the user refresh token.")
	logrus.Trace("RefreshUserTokensIfExpired end")
	return true
}

// GetCSRFToken returns a random string to use as the CSRF token based on the session
func (session Session) GetCSRFToken() string {
	csrfBytes := sha256.Sum256([]byte(session.Id))
	return hex.EncodeToString(csrfBytes[:])
}

// IsValidCSRFToken checks the provided access token against the CSRF token generated from the session
func (session Session) IsValidCSRFToken(actualCSRFToken string) bool {
	return subtle.ConstantTimeCompare([]byte(session.GetCSRFToken()), []byte(actualCSRFToken)) == 1
}

// NewSession creates a new session.
func NewSession(w http.ResponseWriter, r *http.Request) (Session, error) {
	sessInfo := Session{}
	session, err := sessionStore.New(r, USER_SESSION_NAME)
	if err != nil {
		logrus.Debugf("error while trying to create a new session. safe to ignore errors of type 'file not found' for new sessions. Error: %q", err)
	}
	session.ID = "" // This is required to avoid "file not found" error on save. The ID will be set to a random value when saving.
	if err := session.Save(r, w); err != nil {
		return sessInfo, fmt.Errorf("failed to save the new session to the store. Error: %q", err)
	}
	sessInfo.Id = session.ID
	session.Values[SESSION_KEY_SESSION_INFO] = sessInfo
	if err := session.Save(r, w); err != nil {
		return sessInfo, fmt.Errorf("failed to save the new session to the store. Error: %q", err)
	}
	return sessInfo, nil
}

// GetSession returns info about the session. It returns error if the session doesn't exist.
func GetSession(r *http.Request) (Session, error) {
	sessInfo := Session{}
	session, err := sessionStore.Get(r, USER_SESSION_NAME)
	if err != nil {
		return sessInfo, err
	}
	sessInfoI, ok := session.Values[SESSION_KEY_SESSION_INFO]
	if !ok {
		return sessInfo, types.ErrorSessionDoesNotExist{}
	}
	return sessInfoI.(Session), nil
}

// SaveSession updates the info of an existing session.
func SaveSession(w http.ResponseWriter, r *http.Request, sessInfo Session) error {
	session, err := sessionStore.Get(r, USER_SESSION_NAME)
	if err != nil {
		return err
	}
	session.Values[SESSION_KEY_SESSION_INFO] = sessInfo
	return session.Save(r, w)
}

// IsLoggedIn checks if the user has logged in already
func IsLoggedIn(r *http.Request) bool {
	logrus.Trace("IsLoggedIn start")
	session, err := GetSession(r)
	if err != nil {
		logrus.Debugf("failed to get the session. Error: %q", err)
		return false
	}
	if session.Tokens.AccessToken == "" {
		logrus.Debug("the user access token is empty")
		return false
	}
	if decodedBytes, err := authserver.DecodeToken(session.Tokens.AccessToken); err != nil {
		logrus.Debugf("failed to get the decode the token %s . Error: %q", string(decodedBytes), err)
		return false
	}
	logrus.Trace("IsLoggedIn end")
	return true
}
