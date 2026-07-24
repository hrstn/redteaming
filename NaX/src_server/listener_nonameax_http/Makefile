# Makefile - listener_nonameax_http extender plugin
#
# GOEXPERIMENT must match the flags used to build adaptixserver; the Go plugin
# loader checks internal/goexperiment compatibility and rejects mismatches.
# Inspect the server binary with:
#   strings Server/adaptixserver | grep '^go[0-9]'
# Current server: go1.25.4 X:jsonv2,greenteagc

GOEXPERIMENT := jsonv2,greenteagc
DEPLOY_DIR   := ../../../Server/extenders/listener_nonameax_http
OUT          := $(DEPLOY_DIR)/listener_nonameax_http.so

.PHONY: all clean

all: $(OUT)

$(OUT): *.go
	GOEXPERIMENT=$(GOEXPERIMENT) go build -buildmode=plugin -o $(OUT) .
	@echo "  DEPLOY  $(OUT)"

clean:
	rm -f $(OUT)
