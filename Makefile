#!/bin/make
GOROOT:=$(shell PATH="/pkg/main/dev-lang.go.dev/bin:$$PATH" go env GOROOT)
GOPATH:=$(shell $(GOROOT)/bin/go env GOPATH)

.PHONY: test deps race-test

all:
	GOROOT="$(GOROOT)" $(GOPATH)/bin/goimports -w -l .
	$(GOROOT)/bin/go build -v

deps:
	$(GOROOT)/bin/go get -v -t .

test:
	$(GOROOT)/bin/go test -v
	
race-test:
	$(GOROOT)/bin/go test -race -v
