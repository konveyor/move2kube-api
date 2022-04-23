[![Build](https://github.com/konveyor/move2kube-api/workflows/Build/badge.svg "Github Actions")](https://github.com/konveyor/move2kube-api/actions?query=workflow%3ABuild)
[![Docker Repository on Quay](https://quay.io/repository/konveyor/move2kube-api/status "Docker Repository on Quay")](https://quay.io/repository/konveyor/move2kube-api)
[![License](https://img.shields.io/:license-apache-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0.html)
[![contributions welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](https://github.com/konveyor/move2kube-api/pulls)
[![Go Report Card](https://goreportcard.com/badge/github.com/konveyor/move2kube-api)](https://goreportcard.com/report/github.com/konveyor/move2kube-api)
[<img src="https://img.shields.io/badge/slack-konveyor/move2kube-green.svg?logo=slack">](https://kubernetes.slack.com/archives/CR85S82A2)

# Move2Kube-API

Move2Kube API provides a REST interface to interact with move2kube [command line tool](https://github.com/konveyor/move2kube).

## Usage

Run using container from registry using `make crun`

## Setup

1. Obtain a recent version of `golang`. Known to work with `1.18`.
1. Ensure `$GOPATH` is set. If it's not set:
   1. `mkdir ~/go`
   1. `export GOPATH=~/go`
1. Obtain this repo:
   1. `mkdir -p $GOPATH/src/`
   1. Clone this repo into the above directory.
   1. `cd $GOPATH/src/move2kube-api`
1. Build: `make build`
1. Run unit tests: `make test`
1. Run image build: `make cbuild`
1. Run image: `make crun`

## Discussion

* For any questions reach out to us on any of the communication channels given on our website https://move2kube.konveyor.io/
