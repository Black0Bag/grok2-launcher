package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/Black0Bag/grok2-launcher/internal/config"
	"github.com/Black0Bag/grok2-launcher/internal/embed"
	"github.com/Black0Bag/grok2-launcher/internal/logger"
	"github.com/Black0Bag/grok2-launcher/internal/manager"
)

var mgr *manager.Manager

func main() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "加载配置失败: %v\n", err)
		os.Exit(1)
	}

	workDir := filepath.Join(os.TempDir(), "grok2-launcher")
	os.MkdirAll(workDir, 0755)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/api/config", handleConfig(cfg))
	http.HandleFunc("/api/start", handleStart(ctx, workDir, cfg))
	http.HandleFunc("/api/stop", handleStop)
	http.HandleFunc("/api/status", handleStatus)
	http.HandleFunc("/api/logs", handleLogs)

	server := &http.Server{Addr: "127.0.0.1:9527", Handler: nil}

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		if mgr != nil {
			mgr.Stop()
		}
		cancel()
		server.Close()
	}()

	fmt.Println("Grok2 Launcher started at http://127.0.0.1:9527")
	openBrowser("http://127.0.0.1:9527")

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		os.Exit(1)
	}
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data, err := embed.WebUIFile()
	if err != nil {
		http.Error(w, "internal error", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(data)
}

func handleConfig(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			json.NewEncoder(w).Encode(cfg)
		case http.MethodPost:
			var incoming config.Config
			if err := json.NewDecoder(r.Body).Decode(&incoming); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			cfg.PythonPath = incoming.PythonPath
			cfg.YescaptchaKey = incoming.YescaptchaKey
			cfg.TempmailKey = incoming.TempmailKey
			cfg.ProxyPort = incoming.ProxyPort
			cfg.ProxyEnabled = incoming.ProxyEnabled
			if err := config.Save(cfg); err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		}
	}
}

func handleStart(ctx context.Context, workDir string, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", 405)
			return
		}
		if mgr != nil {
			http.Error(w, "already started", 400)
			return
		}
		mgr = manager.New(workDir, cfg.PythonPath, cfg.ProxyPort, cfg.ProxyEnabled, cfg.YescaptchaKey, cfg.TempmailKey)
		go mgr.Start(ctx)
		json.NewEncoder(w).Encode(map[string]string{"status": "starting"})
	}
}

func handleStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	if mgr != nil {
		mgr.Stop()
		mgr = nil
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "stopped"})
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	state := manager.ServiceState{}
	if mgr != nil {
		state = mgr.State()
	}
	json.NewEncoder(w).Encode(state)
}

func handleLogs(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", 500)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := logger.Global.Subscribe()
	defer logger.Global.Unsubscribe(ch)

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case entry, ok := <-ch:
			if !ok {
				return
			}
			data, _ := json.Marshal(entry)
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}

func openBrowser(url string) {
	cmd := "rundll32"
	args := []string{"url.dll,FileProtocolHandler", url}

	if os.Getenv("DISPLAY") != "" {
		cmd = "xdg-open"
		args = []string{url}
	} else if _, err := os.Stat("/mnt/c/Windows"); err == nil {
		cmd = "cmd.exe"
		args = []string{"/c", "start", url}
	}

	proc, err := os.StartProcess(cmd, append([]string{cmd}, args...),
		&os.ProcAttr{Files: []*os.File{nil, nil, nil}})
	if err != nil {
		logger.Global.Write(logger.Warn, "自动打开浏览器失败: %v", err)
	}
	_ = proc
}
