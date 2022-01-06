package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/criteo/haproxy-spoe-auth/internal/agent"
	"github.com/criteo/haproxy-spoe-auth/internal/auth"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

func LogLevelFromLogString(level string) logrus.Level {
	switch level {
	case "info":
		return logrus.InfoLevel
	case "debug":
		return logrus.DebugLevel
	default:
		return logrus.InfoLevel
	}
}

func main() {
	var configFile string
	flag.StringVar(&configFile, "config", "", "The path to the configuration file")
	flag.Parse()

	if configFile != "" {
		viper.SetConfigFile(configFile)
	} else {
		viper.SetConfigName("config") // name of config file (without extension)
		viper.SetConfigType("yaml")   // REQUIRED if the config file does not have the extension in the name
		viper.AddConfigPath(".")      // optionally look for config in the working directory
	}
	err := viper.ReadInConfig() // Find and read the config file
	if err != nil {             // Handle errors reading the config file
		logrus.Panic(fmt.Errorf("fatal error config file: %w", err))
	}

	logrus.SetLevel(LogLevelFromLogString(viper.GetString("server.log_level")))

	authenticators := map[string]auth.Authenticator{}

	if viper.IsSet("ldap") {
		ldapAuthentifier := auth.NewLDAPAuthenticator(auth.LDAPConnectionDetails{
			Hostname:   viper.GetString("ldap.hostname"),
			Port:       viper.GetInt("ldap.port"),
			UserDN:     viper.GetString("ldap.user_dn"),
			Password:   viper.GetString("ldap.password"),
			BaseDN:     viper.GetString("ldap.base_dn"),
			UserFilter: viper.GetString("ldap.user_filter"),
		})
		authenticators["try-auth-ldap"] = ldapAuthentifier
	}

	if viper.IsSet("oidc") {
		// TODO: watch the config file to update the list of clients dynamically
		var clientsConfig map[string]auth.OIDCClientConfig
		err := viper.UnmarshalKey("oidc.clients", &clientsConfig)
		if err != nil {
			logrus.Panic(err)
		}

		oidcAuthenticator := auth.NewOIDCAuthenticator(auth.OIDCAuthenticatorOptions{
			OAuth2AuthenticatorOptions: auth.OAuth2AuthenticatorOptions{
				RedirectCallbackPath: viper.GetString("oidc.oauth2_callback_path"),
				LogoutPath:           viper.GetString("oidc.oauth2_logout_path"),
				HealthCheckPath:      viper.GetString("oidc.oauth2_healthcheck_path"),
				CallbackAddr:         viper.GetString("oidc.callback_addr"),
				CookieName:           viper.GetString("oidc.cookie_name"),
				CookieSecure:         viper.GetBool("oidc.cookie_secure"),
				CookieTTL:            viper.GetDuration("oidc.cookie_ttl_seconds") * time.Second,
				SignatureSecret:      viper.GetString("oidc.signature_secret"),
				ClientsStore:         auth.NewStaticOIDCClientStore(clientsConfig),
			},
			ProviderURL:      viper.GetString("oidc.provider_url"),
			EncryptionSecret: viper.GetString("oidc.encryption_secret"),
		})
		authenticators["try-auth-oidc"] = oidcAuthenticator
	}

	agent.StartAgent(viper.GetString("server.addr"), authenticators)
}
