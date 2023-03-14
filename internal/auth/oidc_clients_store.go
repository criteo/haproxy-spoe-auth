package auth

import (
	"strings"
)

type OIDCClientConfig struct {
	ClientID     string `mapstructure:"client_id"`
	ClientSecret string `mapstructure:"client_secret"`
	RedirectURL  string `mapstructure:"redirect_url"`
}

type OIDCClientsStore interface {
	// Retrieve the client_id and client_secret based on the domain
	GetClient(domain string) (*OIDCClientConfig, error)
	AddClient(domain string, clientid string, clientsecret string, redirecturl string)
}

type StaticOIDCClientsStore struct {
	clients map[string]OIDCClientConfig
}

func NewStaticOIDCClientStore(config map[string]OIDCClientConfig) *StaticOIDCClientsStore {
	return &StaticOIDCClientsStore{clients: config}
}

func NewEmptyStaticOIDCClientStore() *StaticOIDCClientsStore {
	return &StaticOIDCClientsStore{clients: map[string]OIDCClientConfig{}}
}

func (ocf *StaticOIDCClientsStore) GetClient(domain string) (*OIDCClientConfig, error) {
	if config, ok := ocf.clients[domain]; ok {
		return &config, nil
	}
	return nil, ErrOIDCClientConfigNotFound
}

func (ocf *StaticOIDCClientsStore) AddClient(domain string, clientid string, clientsecret string, redirecturl string) {
	if _, ok := ocf.clients[domain]; !ok {
		ocf.clients[strings.Clone(domain)] = OIDCClientConfig {
			ClientID: strings.Clone(clientid),
			ClientSecret: strings.Clone(clientsecret),
			RedirectURL: strings.Clone(redirecturl),
		}
	}
}
