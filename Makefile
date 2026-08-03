.PHONY: test build clean

build:
	mkdir -p dist
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=0.1.0-dev" -o dist/certarium ./cmd/certarium

test:
	go test ./...

clean:
	rm -f dist/certarium
