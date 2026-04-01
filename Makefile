ifeq ($(OS),Windows_NT)
    EXE = .exe
    RM = del /Q /F
    CP = copy /Y
    MKDIR = mkdir
    INSTALL_DIR = C:\Windows\System32
    TARGET_BIN = target\release\kryptos$(EXE)
    SAFE_MKDIR = if not exist $(INSTALL_DIR) $(MKDIR) $(INSTALL_DIR)
else
    EXE =
    RM = rm -rf
    CP = cp
    MKDIR = mkdir -p
    UNAME_S := $(shell uname -s)
    ifeq ($(UNAME_S),Darwin)
        INSTALL_DIR = /usr/local/bin
    else
        INSTALL_DIR = /usr/bin
    endif
    TARGET_BIN = target/release/kryptos$(EXE)
    SAFE_MKDIR = $(MKDIR) $(INSTALL_DIR)
endif

all: build

build:
	cargo build --release

install:
	@$(SAFE_MKDIR)
	@if [ ! -f $(TARGET_BIN) ] && [ "$(OS)" != "Windows_NT" ]; then \
		echo "Error: Binary not found. Run 'make build' as your normal user first."; \
		exit 1; \
	fi
	$(CP) $(TARGET_BIN) $(INSTALL_DIR)

clean:
	cargo clean