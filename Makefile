GO ?= go
TESTFLAGS ?= -race -count=1 -timeout=120s
GOOS := $(shell $(GO) env GOOS)
RPC_TARGET := frida/testdata/bin/rpc-target

.PHONY: test-integration clean
.DELETE_ON_ERROR:

ifeq ($(filter darwin linux,$(GOOS)),)
test-integration:
	@echo "Native RPC tests require macOS or Linux" >&2
	@exit 1
else
test-integration: $(RPC_TARGET)
	$(GO) test -tags=integration $(TESTFLAGS) ./frida

$(RPC_TARGET): frida/testdata/rpc-target.c
	mkdir -p "$(@D)"
	$(CC) $(CPPFLAGS) $(CFLAGS) "$<" -o "$@" $(LDFLAGS) $(LDLIBS)
ifeq ($(GOOS),darwin)
	/usr/bin/codesign --force --sign - --entitlements frida/testdata/rpc-target.entitlements "$@"

$(RPC_TARGET): frida/testdata/rpc-target.entitlements
endif
endif

clean:
	rm -f "$(RPC_TARGET)"
