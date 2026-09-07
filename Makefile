GO ?= go
BIN := bin

.PHONY: all build guest test race vet fmt integration clean
all: build
build:
	mkdir -p $(BIN)
	$(GO) build -trimpath -o $(BIN)/niflhel ./cmd/niflhel
	$(GO) build -trimpath -o $(BIN)/niflheld ./cmd/niflheld
	$(GO) build -trimpath -o $(BIN)/niflhel-pack ./cmd/niflhel-pack
	$(GO) build -trimpath -o $(BIN)/niflhel-pack-ssh ./cmd/niflhel-pack-ssh
	$(MAKE) guest
guest:
	mkdir -p $(BIN)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -o $(BIN)/niflhel-agent ./cmd/niflhel-agent
test:
	$(GO) test ./...
race:
	$(GO) test -race ./...
vet:
	$(GO) vet ./...
fmt:
	gofmt -w cmd internal tests
integration:
	$(GO) test -tags=integration -v ./tests/integration
clean:
	rm -rf bin
