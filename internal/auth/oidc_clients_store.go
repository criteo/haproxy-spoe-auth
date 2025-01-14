package auth

import "sync"

type OIDCClientConfig struct {
	ClientID     string `mapstructure:"client_id"`
	ClientSecret string `mapstructure:"client_secret"`
	RedirectURL  string `mapstructure:"redirect_url"`
}

type OIDCClientsStore interface {
	// Retrieve the client_id and client_secret based on the domain
	GetClient(domain string) (*OIDCClientConfig, error)
	AddClient(domain, clientid, clientsecret, redirecturl string)
}

type StaticOIDCClientsStore struct {
	clients map[string]OIDCClientConfig

	mtx sync.RWMutex
}

func NewStaticOIDCClientStore(config map[string]OIDCClientConfig) *StaticOIDCClientsStore {
	// Copy data.
	clients := make(map[string]OIDCClientConfig, len(config))

	for k, v := range config {
		clients[k] = OIDCClientConfig{
			ClientID:     v.ClientID,
			ClientSecret: v.ClientSecret,
			RedirectURL:  v.RedirectURL,
		}
	}

	return &StaticOIDCClientsStore{clients: clients}
}

func NewEmptyStaticOIDCClientStore() *StaticOIDCClientsStore {
	return &StaticOIDCClientsStore{clients: map[string]OIDCClientConfig{}}
}

func (ocf *StaticOIDCClientsStore) GetClient(domain string) (*OIDCClientConfig, error) {
	ocf.mtx.RLock()
	defer ocf.mtx.RUnlock()

	if config, ok := ocf.clients[domain]; ok {
		return &config, nil
	}
	return nil, ErrOIDCClientConfigNotFound
}

func (ocf *StaticOIDCClientsStore) AddClient(domain, clientid, clientsecret, redirecturl string) {
	ocf.mtx.Lock()
	defer ocf.mtx.Unlock()

	if _, ok := ocf.clients[domain]; !ok {
		ocf.clients[domain] = OIDCClientConfig{
			ClientID:     clientid,
			ClientSecret: clientsecret,
			RedirectURL:  redirecturl,
		}
	}
}
