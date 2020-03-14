PROJECT_NAME = pcapng2pcap
CWD_DIR = ./cwd/
BIN_DIR = ./bin/
TEST_DIR = ./test/
SCRIPTS_DIR = ./scripts/
TMP_DIR = ./tmp/

PRODUCTION_VERSION = 0.1.0
GIT_COMMIT := $(shell git rev-parse --short=12 HEAD)
LD_FLAGS = "-X 'main.version=$(PRODUCTION_VERSION)' -X 'main.gitCommit=$(GIT_COMMIT)'"

.PHONY: test

all: clean dep test build

dep:
	@echo -n "Downloading Dependencies: "
	@go get -d ./...
	@echo "[OK]"

clean:
	@echo -n "Cleaning: "
	@rm -rf $(TMP_DIR)
	@rm -rf $(BIN_DIR)
	@echo "[OK]"

test:
	@mkdir -p $(TMP_DIR)
	@for f in $(SCRIPTS_DIR)*_test.sh; do \
		bash "$$f" 'go run -ldflags $(LD_FLAGS) $(CWD_DIR)$(PROJECT_NAME)/$(PROJECT_NAME).go' '$(TEST_DIR)' '$(TMP_DIR)' || exit 1; \
	done
	@rm -rf $(TMP_DIR)

build:
	@echo -n "Building: "
	@mkdir -p $(BIN_DIR)
	@go build -ldflags $(LD_FLAGS) -o $(BIN_DIR)$(PROJECT_NAME) $(CWD_DIR)$(PROJECT_NAME)
	@echo "[OK]"

install:
	@echo -n "Installing: "
	@go install -ldflags $(LD_FLAGS) $(CWD_DIR)$(PROJECT_NAME)
	@echo "[OK]"

run:
	@go run -ldflags $(LD_FLAGS) $(CWD_DIR)$(PROJECT_NAME)/$(PROJECT_NAME).go

compile:
	@echo "Compiling: "
	@mkdir -p $(BIN_DIR)

	# FreeBDS (32bit)
	GOOS=freebsd GOARCH=386 go build -ldflags $(LD_FLAGS) -o $(BIN_DIR)$(PROJECT_NAME)-freebsd_32bit $(CWD_DIR)$(PROJECT_NAME)
	# MacOS (32bit)
	GOOS=darwin GOARCH=386 go build -ldflags $(LD_FLAGS) -o $(BIN_DIR)$(PROJECT_NAME)-darwin_32bit $(CWD_DIR)$(PROJECT_NAME)
	# Linux (32bit)
	GOOS=linux GOARCH=386 go build -ldflags $(LD_FLAGS) -o $(BIN_DIR)$(PROJECT_NAME)-linux_32bit $(CWD_DIR)$(PROJECT_NAME)
	# Windows (32bit)
	GOOS=windows GOARCH=386 go build -ldflags $(LD_FLAGS) -o $(BIN_DIR)$(PROJECT_NAME)-windows_32bit.exe $(CWD_DIR)$(PROJECT_NAME)

	# FreeBDS (64bit)
	GOOS=freebsd GOARCH=amd64 go build -ldflags $(LD_FLAGS) -o $(BIN_DIR)$(PROJECT_NAME)-freebsd_64bit $(CWD_DIR)$(PROJECT_NAME)
	# MacOS (64bit)
	GOOS=darwin GOARCH=amd64 go build -ldflags $(LD_FLAGS) -o $(BIN_DIR)$(PROJECT_NAME)-darwin_64bit $(CWD_DIR)$(PROJECT_NAME)
	# Linux (64bit)
	GOOS=linux GOARCH=amd64 go build -ldflags $(LD_FLAGS) -o $(BIN_DIR)$(PROJECT_NAME)-linux_64bit $(CWD_DIR)$(PROJECT_NAME)
	# Windows (64bit)
	GOOS=windows GOARCH=amd64 go build -ldflags $(LD_FLAGS) -o $(BIN_DIR)$(PROJECT_NAME)-windows_64bit.exe $(CWD_DIR)$(PROJECT_NAME)

	@echo "[OK]"
