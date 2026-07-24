# NaX src_server/Makefile
# Builds extender plugins and deploys to Server/extenders/.
# Usage:  make -C src_server
#         make -C src_server SERVER_DIR=/path/to/Server GOEXPERIMENT=jsonv2,greenteagc
#
# SERVER_DIR, GO, and GOEXPERIMENT are overridable (setup_nax.sh passes them).
# GOEXPERIMENT must match the flags used to build adaptixserver.
# Auto-detect with:  strings Server/adaptixserver | grep '^go[0-9]'

NAX_ROOT    := $(shell cd .. && pwd)
REPO_ROOT   := $(shell cd ../.. && pwd)
SERVER_DIR  ?= $(REPO_ROOT)/Server
AGENT_DIR   := $(NAX_ROOT)/src_server/agent_nonameax
LISTENER_DIR     := $(NAX_ROOT)/src_server/listener_nonameax_http
LISTENER_SMB_DIR := $(NAX_ROOT)/src_server/listener_nonameax_smb
SERVICE_DIR      := $(NAX_ROOT)/src_server/service_nax_store
DEPLOY_AGENT        := $(SERVER_DIR)/extenders/agent_nonameax
DEPLOY_LISTENER     := $(SERVER_DIR)/extenders/listener_nonameax_http
DEPLOY_LISTENER_SMB := $(SERVER_DIR)/extenders/listener_nonameax_smb
DEPLOY_SERVICE      := $(SERVER_DIR)/extenders/service_nax_store

GO           ?= /usr/local/go/bin/go
GOEXPERIMENT ?= jsonv2,greenteagc

.PHONY: all clean test agent listener listener-smb service

all: agent listener listener-smb service

agent:
	@echo "  BUILD  agent_nonameax.so"
	@cd $(AGENT_DIR) && GOEXPERIMENT=$(GOEXPERIMENT) $(GO) build -buildmode=plugin \
		-o $(DEPLOY_AGENT)/agent_nonameax.so .
	@cp $(AGENT_DIR)/ax_config.axs $(DEPLOY_AGENT)/ax_config.axs
	@cp $(AGENT_DIR)/config.yaml   $(DEPLOY_AGENT)/config.yaml
	@cp -r $(AGENT_DIR)/pe_templates $(DEPLOY_AGENT)/pe_templates
	@echo "  DEPLOY $(DEPLOY_AGENT)/"

listener:
	@echo "  BUILD  listener_nonameax_http.so"
	@cd $(LISTENER_DIR) && GOEXPERIMENT=$(GOEXPERIMENT) $(GO) build -buildmode=plugin \
		-o $(DEPLOY_LISTENER)/listener_nonameax_http.so .
	@cp $(LISTENER_DIR)/ax_config.axs $(DEPLOY_LISTENER)/ax_config.axs
	@cp $(LISTENER_DIR)/config.yaml   $(DEPLOY_LISTENER)/config.yaml
	@echo "  DEPLOY $(DEPLOY_LISTENER)/"

listener-smb:
	@echo "  BUILD  listener_nonameax_smb.so"
	@mkdir -p $(DEPLOY_LISTENER_SMB)
	@cd $(LISTENER_SMB_DIR) && GOEXPERIMENT=$(GOEXPERIMENT) $(GO) build -buildmode=plugin \
		-o $(DEPLOY_LISTENER_SMB)/listener_nonameax_smb.so .
	@cp $(LISTENER_SMB_DIR)/ax_config.axs $(DEPLOY_LISTENER_SMB)/ax_config.axs
	@cp $(LISTENER_SMB_DIR)/config.yaml   $(DEPLOY_LISTENER_SMB)/config.yaml
	@echo "  DEPLOY $(DEPLOY_LISTENER_SMB)/"

service:
	@echo "  BUILD  nax_store.so"
	@mkdir -p $(DEPLOY_SERVICE)
	@cd $(SERVICE_DIR) && GOEXPERIMENT=$(GOEXPERIMENT) $(GO) build -buildmode=plugin \
		-ldflags="-s -w" -o $(DEPLOY_SERVICE)/nax_store.so .
	@cp $(SERVICE_DIR)/ax_config.axs $(DEPLOY_SERVICE)/ax_config.axs
	@cp $(SERVICE_DIR)/config.yaml   $(DEPLOY_SERVICE)/config.yaml
	@echo "  DEPLOY $(DEPLOY_SERVICE)/"

test:
	@echo "  TEST   agent_nonameax"
	@cd $(AGENT_DIR)    && $(GO) test ./...
	@echo "  TEST   listener_nonameax_http"
	@cd $(LISTENER_DIR) && $(GO) test ./...

clean:
	@rm -f $(DEPLOY_AGENT)/agent_nonameax.so
	@rm -f $(DEPLOY_LISTENER)/listener_nonameax_http.so
	@rm -f $(DEPLOY_LISTENER_SMB)/listener_nonameax_smb.so
	@rm -f $(DEPLOY_SERVICE)/nax_store.so
	@echo "  CLEAN  done"
