BINARY  := envseal
GOFLAGS := -trimpath

.PHONY: build test lint fmt coverage clean

build:
	go build $(GOFLAGS) -o $(BINARY) .

test:
	go test ./...

lint:
	golangci-lint run ./...

fmt:
	gofmt -w .
	goimports -w .

coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

clean:
	rm -f $(BINARY) coverage.out coverage.html
