package config

import (
	"os"

	"gopkg.in/yaml.v3"

	"github.com/ekristen/oidc-zero/pkg/storage"
)

type Config struct {
	Clients      []*Client         `json:"clients" yaml:"clients"`
	Users        []*storage.User   `json:"users" yaml:"users"`
	ServiceUsers []*storage.Client `json:"service_users" yaml:"service_users"`
}

type Client struct {
	Type         string   `json:"type" yaml:"type"`
	ID           string   `json:"id" yaml:"id"`
	Secret       string   `json:"secret" yaml:"secret"`
	RedirectURIs []string `json:"redirect_uris" yaml:"redirect_uris"`
}

func New(path string) (*Config, error) {
	cfgRaw, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	if cfgRaw == nil {
		return &Config{}, nil
	}

	cfg := &Config{}
	err = yaml.Unmarshal(cfgRaw, cfg)
	if err != nil {
		return nil, err
	}

	return cfg, nil
}
