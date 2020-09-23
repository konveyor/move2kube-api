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
RUN yum install -y make
WORKDIR $GOPATH/src/move2kube-api
COPY go.mod .
COPY go.sum .
COPY Makefile .
RUN make get
COPY . .
# Build
RUN make install

# Run image
FROM move2kube:latest
# Install move2kube-api
COPY --from=build_base /go/bin/move2kube-api /bin/move2kube-api
# Start app
WORKDIR /wksps
EXPOSE 8080
CMD ["move2kube-api"]