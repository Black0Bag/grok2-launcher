# Grok2 Launcher

All-in-one Windows launcher for the **grok2api** + **grok-build-auth** stack.

## What it does

1. Starts **grok2api** (Go API gateway for Grok models)
2. Sets up **Python environment** (embeddable Python compatible)
3. Starts **registration WebUI** for creating x.ai/Grok accounts
4. Initializes API keys via grok2api admin API

## Usage

1. Download `grok2-launcher.exe` from [Releases](https://github.com/Black0Bag/grok2-launcher/releases)
2. Double-click to run
3. Fill in configuration (Python path, API keys)
4. Click Start

## Build from source

```bash
# Clone with submodules
git clone --recursive https://github.com/Black0Bag/grok2-launcher.git

# Build grok2api
cd grok2api/backend
go build -o ../../internal/embed/grok2api.exe ./cmd/grok2api

# Build launcher
cd ../..
go build -o grok2-launcher.exe ./cmd/launcher
```
