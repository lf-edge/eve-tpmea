# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

REPO_ROOT = $(abspath ..)
BUILD_DIR = bin
SERVER    = $(BUILD_DIR)/tpmea-server
CLIENT    = $(BUILD_DIR)/tpmea-client

.PHONY: all build server client run clean

all: build

build: server client

server:
	@mkdir -p $(BUILD_DIR)
	cd $(REPO_ROOT) && go build -buildvcs=false -o cmd/$(SERVER) ./cmd/server

client:
	@mkdir -p $(BUILD_DIR)
	cd $(REPO_ROOT) && go build -buildvcs=false -o cmd/$(CLIENT) ./cmd/client

run: build
	@bash run-demo.sh $(SERVER) $(CLIENT)

clean:
	rm -rf $(BUILD_DIR)
