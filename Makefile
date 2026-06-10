PROTOC  ?= protoc
GOBIN   := $(shell go env GOPATH)/bin
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.1.0-dev)
LDFLAGS := -X osie.cloud/geneza/internal/version.Version=$(VERSION)
BINS    := geneza-gateway geneza-relay geneza-agent geneza-bootstrap geneza geneza-sign

.PHONY: all proto build test vet fmt clean

all: build

proto:
	PATH=$$PATH:$(GOBIN) $(PROTOC) -I api/proto \
		--go_out=paths=source_relative:internal/pb \
		--go-grpc_out=paths=source_relative:internal/pb \
		api/proto/geneza/v1/*.proto

build:
	@mkdir -p bin
	@for b in $(BINS); do \
		echo "building $$b"; \
		CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$$b ./cmd/$$b || exit 1; \
	done

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w $$(git ls-files '*.go' | grep -v /pb/)

clean:
	rm -rf bin
