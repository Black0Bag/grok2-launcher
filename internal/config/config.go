package config

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type Config struct {
	PythonPath    string `json:"python_path"`
	YescaptchaKey string `json:"yescaptcha_key"`
	TempmailKey   string `json:"tempmail_key"`
	ProxyPort     int    `json:"proxy_port"`
	ProxyEnabled  bool   `json:"proxy_enabled"`
	FirstRun      bool   `json:"first_run"`
}

const configFileName = "grok2-launcher-config.json"

func ConfigPath() string {
	exe, err := os.Executable()
	if err == nil {
		return filepath.Join(filepath.Dir(exe), configFileName)
	}
	return configFileName
}

func Load() (*Config, error) {
	data, err := os.ReadFile(ConfigPath())
	if err != nil {
		return &Config{FirstRun: true}, nil
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return &Config{FirstRun: true}, nil
	}
	cfg.FirstRun = false
	return &cfg, nil
}

func Save(cfg *Config) error {
	cfg.FirstRun = false
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(ConfigPath(), data, 0644)
}
