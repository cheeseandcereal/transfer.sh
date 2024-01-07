LDFLAGS := -X github.com/dutchcoders/transfer.sh/cmd.Version=$(shell git log --format="%H" -n 1 | head -c 7) -a -s -w -extldflags "-static"
BINARY := transfersh
UNIXPLATFORMS := linux darwin
os = $(word 1, $@)

.PHONY: $(UNIXPLATFORMS)
$(UNIXPLATFORMS):
	mkdir -p build
	CGO_ENABLED=0 GOOS=$(os) GOARCH=amd64 go build -tags netgo -v -ldflags '$(LDFLAGS)' -o build/$(BINARY)-$(os)-amd64 main.go

.PHONY: windows
windows:
	mkdir -p build
	CGO_ENABLED=0 GOOS=$(os) GOARCH=amd64 go build -tags netgo -v -ldflags '$(LDFLAGS)' -o build/$(BINARY)-$(os)-amd64.exe main.go

.PHONY: linux-arm64
linux-arm64:
	mkdir -p build
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -tags netgo -v -ldflags '$(LDFLAGS)' -o build/$(BINARY)-linux-arm64 main.go

.PHONY: release
release: linux linux-arm64 darwin windows

clean:
	rm -rf build
