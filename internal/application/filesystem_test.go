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

package application_test

import (
	"testing"

	"github.com/konveyor/move2kube-api/internal/application"
)

func TestNormalizeAssetName(t *testing.T) {
	tcs := []struct {
		filename            string
		shouldErr           bool
		wantArchiveName     string
		wantExpandedDirName string
	}{
		{"foo.zip", false, "foo.zip", "foo"},
		{"foo.rem", true, "", ""},
		{"foo.rem.abc", true, "", ""},
		{"lang-plat.zip", false, "lang-plat.zip", "lang-plat"},
		{"lang-plat.tar", false, "lang-plat.tar", "lang-plat"},
		{"lang-plat.tgz", false, "lang-plat.tgz", "lang-plat"},
		{"lang-plat.tar.gz", false, "lang-plat.tar.gz", "lang-plat"},
		{"lang plat.tar.gz", false, "lang-plat.tar.gz", "lang-plat"},
		{"foo/bar/baz.tgz", false, "baz.tgz", "baz"},
		{"../../../bin/ls.tgz", false, "ls.tgz", "ls"},
		{"../../../bin/ls.tar.gz", false, "ls.tar.gz", "ls"},
	}
	for _, tc := range tcs {
		archiveName, expandedDirName, err := application.NormalizeAssetName(tc.filename)
		if tc.shouldErr {
			if err == nil {
				t.Fatalf("expected there to be an error on %s", tc.filename)
			}
			continue
		}
		if err != nil {
			t.Fatalf("failed to normalize the asset filename %s . Error: %q", tc.filename, err)
		}
		if archiveName != tc.wantArchiveName {
			t.Fatalf("the archive name is not correct. Expected: %s Actual: %s", tc.wantArchiveName, archiveName)
		}
		if expandedDirName != tc.wantExpandedDirName {
			t.Fatalf("the expanded dir name is not correct. Expected: %s Actual: %s", tc.wantExpandedDirName, expandedDirName)
		}
		// check if it is idempotent when given the archive name again as input
		x, y, err := application.NormalizeAssetName(archiveName)
		if err != nil {
			t.Fatalf("failed to normalize the asset filename %s . Error: %q", tc.filename, err)
		}
		if x != tc.wantArchiveName {
			t.Fatalf("the archive name is not idempotent. Expected: %s Actual: %s", tc.wantArchiveName, x)
		}
		if y != tc.wantExpandedDirName {
			t.Fatalf("the expanded dir name is not idempotent. Expected: %s Actual: %s", tc.wantExpandedDirName, y)
		}
	}
}
