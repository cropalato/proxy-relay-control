IMAGE ?= ghcr.io/cropalato/proxy-relay-control
TAG   ?= dev

.PHONY: build test vet fmt lint image chart e2e clean

build:
	go build -o bin/relay ./cmd/relay

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

lint: fmt vet test

image:
	docker build -t $(IMAGE):$(TAG) .

chart:
	helm lint deploy/helm
	helm template relay deploy/helm -n relay-system >/dev/null

# End-to-end against a kind cluster. See docs/testing.md for what it asserts.
e2e:
	./hack/e2e.sh

clean:
	rm -rf bin
