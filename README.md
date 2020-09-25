[![Build Status](https://travis-ci.org/konveyor/move2kube-api.svg?branch=master)](https://travis-ci.org/konveyor/move2kube-api)
[![License](http://img.shields.io/:license-apache-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0.html)
[![contributions welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](https://github.com/konveyor/move2kube-api/pulls)
[![Go Report Card](https://goreportcard.com/badge/github.com/konveyor/move2kube-api)](https://goreportcard.com/report/github.com/konveyor/move2kube-api)
[<img src="http://img.shields.io/badge/slack-konveyor/move2kube-green.svg?logo=slack">](https://cloud-native.slack.com/archives/C01AJ5WCXGF)

# move2kube-api

Move2Kube API provides a REST interface to interact with move2kube [command line tool](https://github.com/konveyor/move2kube).

## Setup

1. Obtain a recent version of `golang`. Known to work with `1.15`.
1. Ensure `$GOPATH` is set. If it's not set:
   1. `mkdir ~/go`
   1. `export GOPATH=~/go`
1. Obtain this repo:
   1. `mkdir -p $GOPATH/src/`
   1. Clone this repo into the above directory.
   1. `cd $GOPATH/src/move2kube-api`
1. Build: `make build`
1. Run unit tests: `make test`

## Discussion

To discuss with the maintainers, reach out in [slack](https://cloud-native.slack.com/archives/C01AJ5WCXGF) in [cloud-native](https://slack.cncf.io/) workspace.
