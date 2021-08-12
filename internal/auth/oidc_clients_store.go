package auth

type OIDCClientConfig struct {
	ClientID     string `mapstructure:"client_id"`
	ClientSecret string `mapstructure:"client_secret"`
	RedirectURL  string `mapstructure:"redirect_url"`
}

type OIDCClientsStore interface {
	// Retrieve the client_id and client_secret based on the domain
	GetClient(domain string) (*OIDCClientConfig, error)
}

type StaticOIDCClientsStore struct {
	clients map[string]OIDCClientConfig
}

func NewStaticOIDCClientStore(config map[string]OIDCClientConfig) *StaticOIDCClientsStore {
	return &StaticOIDCClientsStore{clients: config}
}

func (ocf *StaticOIDCClientsStore) GetClient(domain string) (*OIDCClientConfig, error) {
	if config, ok := ocf.clients[domain]; ok {
		return &config, nil
	}
	return nil, ErrOIDCClientConfigNotFound
}
