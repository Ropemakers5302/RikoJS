package config

import (
	"os"
	"sync"

	"gopkg.in/yaml.v3"
)

type AIConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Provider string `yaml:"provider"`
	APIKey   string `yaml:"api_key"`
	APIBase  string `yaml:"api_base"`
	Model    string `yaml:"model"`
}

type ScanConfig struct {
	Threads    int `yaml:"threads"`
	Timeout    int `yaml:"timeout"`
	MaxRetries int `yaml:"max_retries"`
}

type OutputConfig struct {
	Verbose     bool   `yaml:"verbose"`
	SaveResults bool   `yaml:"save_results"`
	OutputFile  string `yaml:"output_file"`
}

type Config struct {
	AI     AIConfig     `yaml:"ai"`
	Scan   ScanConfig   `yaml:"scan"`
	Output OutputConfig `yaml:"output"`
}

var (
	globalConfig *Config
	once         sync.Once
)

func Load(configPath string) (*Config, error) {
	var err error
	once.Do(func() {
		globalConfig = &Config{
			AI: AIConfig{
				Enabled:  false,
				Provider: "openai",
				APIBase:  "https://api.openai.com/v1",
				Model:    "gpt-4",
			},
			Scan: ScanConfig{
				Threads:    25,
				Timeout:    10,
				MaxRetries: 3,
			},
			Output: OutputConfig{
				Verbose:     false,
				SaveResults: true,
				OutputFile:  "results.json",
			},
		}

		if configPath != "" {
			data, readErr := os.ReadFile(configPath)
			if readErr != nil {
				err = readErr
				return
			}
			if parseErr := yaml.Unmarshal(data, globalConfig); parseErr != nil {
				err = parseErr
				return
			}
		}
	})
	return globalConfig, err
}

func Get() *Config {
	if globalConfig == nil {
		Load("")
	}
	return globalConfig
}
