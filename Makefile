PROJECT_NAME = pcapng2pcap
CWD_DIR = ./cwd/
BIN_DIR = ./bin/

all: test build

build:
	mkdir -p $(BIN_DIR)
	go build -o $(BIN_DIR)$(PROJECT_NAME) $(CWD_DIR)$(PROJECT_NAME)

run:
	go run $(CWD_DIR)$(PROJECT_NAME)

compile:
	mkdir -p $(BIN_DIR)
	# FreeBDS (32bit)
	GOOS=freebsd GOARCH=386 go build -o $(BIN_DIR)$(PROJECT_NAME)-freebsd_32bit $(CWD_DIR)$(PROJECT_NAME)
	# MacOS (32bit)
	GOOS=darwin GOARCH=386 go build -o $(BIN_DIR)$(PROJECT_NAME)-darwin_32bit $(CWD_DIR)$(PROJECT_NAME)
	# Linux (32bit)
	GOOS=linux GOARCH=386 go build -o $(BIN_DIR)$(PROJECT_NAME)-linux_32bit $(CWD_DIR)$(PROJECT_NAME)
	# Windows (32bit)
	GOOS=windows GOARCH=386 go build -o $(BIN_DIR)$(PROJECT_NAME)-windows_32bit.exe $(CWD_DIR)$(PROJECT_NAME)

	# FreeBDS (64bit)
	GOOS=freebsd GOARCH=amd64 go build -o $(BIN_DIR)$(PROJECT_NAME)-freebsd_64bit $(CWD_DIR)$(PROJECT_NAME)
	# MacOS (64bit)
	GOOS=darwin GOARCH=amd64 go build -o $(BIN_DIR)$(PROJECT_NAME)-darwin_64bit $(CWD_DIR)$(PROJECT_NAME)
	# Linux (64bit)
	GOOS=linux GOARCH=amd64 go build -o $(BIN_DIR)$(PROJECT_NAME)-linux_64bit $(CWD_DIR)$(PROJECT_NAME)
	# Windows (64bit)
	GOOS=windows GOARCH=amd64 go build -o $(BIN_DIR)$(PROJECT_NAME)-windows_64bit.exe $(CWD_DIR)$(PROJECT_NAME)
