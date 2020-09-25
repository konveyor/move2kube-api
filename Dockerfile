#   Copyright IBM Corporation 2020
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

ARG VERSION=latest
# Build image
FROM registry.access.redhat.com/ubi8/ubi:latest AS build_base

# Get Dependencies
WORKDIR /temp
RUN curl -o go.tar.gz https://dl.google.com/go/go1.15.linux-amd64.tar.gz
RUN tar -xzf go.tar.gz && mv go /usr/local/

# Get go
ENV GOPATH=/go
WORKDIR $GOPATH
ENV PATH=$GOPATH/bin:/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
RUN mkdir -p $GOPATH/src $GOPATH/bin && chmod -R 777 $GOPATH
# Download source and build
RUN yum install git make -y 
WORKDIR $GOPATH/src/move2kube-api
COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .
# Build
RUN make build 

# Run image
FROM quay.io/konveyor/move2kube:$VERSION
# Install move2kube-api
COPY --from=build_base /go/bin/move2kube-api /bin/move2kube-api
# Start app
WORKDIR /wksps
EXPOSE 8080
CMD ["move2kube-api"]
