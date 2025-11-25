package main

import (
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"time"

	"github.com/criteo/haproxy-spoe-auth/internal/agent"
	"github.com/criteo/haproxy-spoe-auth/internal/auth"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// DefaultStateTTL is the amount of time before the state is considered expired. This will be replaced
// by an expiration in a JWT token in a future review.
const DefaultStateTTL = 5 * time.Minute

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

type flagsConfig struct {
	dynamicClientInfo bool
	configFile        string
	pprofBind         string
}

func parseFlags() flagsConfig {
	var cfg flagsConfig

	pflag.StringP("config", "c", "", "The path to the configuration file")
	pflag.BoolP("dynamic", "d", false, "Dynamically read client information")
	pflag.StringP("pprof", "p", "", "pprof socket to listen to")
	pflag.Parse()

	if err := viper.BindPFlags(pflag.CommandLine); err != nil {
		logrus.WithError(err).Fatalln("Can not init cmd flags")
	}

	viper.SetEnvPrefix("HAPROXY_SPOE_AUTH")

	vars := []string{"config", "dynamic", "pprof"}
	for _, v := range vars {
		if err := viper.BindEnv(v); err != nil {
			logrus.WithError(err).Fatalln("Can not bind Viper environment variable")
		}
	}

	cfg.configFile = viper.GetString("config")
	cfg.dynamicClientInfo = viper.GetBool("dynamic")
	cfg.pprofBind = viper.GetString("pprof")

	return cfg
}

func main() {
	flagsCfg := parseFlags()

	if flagsCfg.configFile != "" {
		viper.SetConfigFile(flagsCfg.configFile)
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

	if viper.GetBool("server.log_json") {
		logrus.SetFormatter(&logrus.JSONFormatter{})
	}

	logrus.WithFields(logrus.Fields{
		"config":              flagsCfg.configFile,
		"dynamic-client-info": flagsCfg.dynamicClientInfo,
		"pprof":               flagsCfg.pprofBind,
	}).Info("Command line flags")

	authenticators := map[string]auth.Authenticator{}

	if viper.IsSet("ldap") {
		var SPOEMessageName = viper.GetString("ldap.spoe_message")
		if SPOEMessageName == "" {
			logrus.Fatal("Configuration field ldap.spoe_message is not defined")
		}

		var ldapConnCfg = auth.LDAPConnectionDetails{
			URI:        viper.GetString("ldap.uri"),
			Port:       viper.GetInt("ldap.port"),
			UserDN:     viper.GetString("ldap.user_dn"),
			Password:   viper.GetString("ldap.password"),
			BaseDN:     viper.GetString("ldap.base_dn"),
			UserFilter: viper.GetString("ldap.user_filter"),
			VerifyTLS:  viper.GetBool("ldap.verify_tls"),
		}

		ldapAuthentifier := auth.NewLDAPAuthenticator(ldapConnCfg)
		authenticators[SPOEMessageName] = ldapAuthentifier

		// Print configuration.
		logrus.WithFields(logrus.Fields{
			"authenticator": "LDAP",
			"SPOE_message":  SPOEMessageName,
			"URI":           ldapConnCfg.URI,
			"port":          ldapConnCfg.Port,
			"user_dn":       ldapConnCfg.UserDN,
			"user_filter":   ldapConnCfg.UserFilter,
			"tls_verify":    ldapConnCfg.VerifyTLS,
		}).Info("LDAP authenticator configuration")
	} else {
		logrus.WithField("authenticator", "LDAP").Info("LDAP authentication is not configured")
	}

	if viper.IsSet("oidc") {
		var SPOEMessageName = viper.GetString("oidc.spoe_message")
		if SPOEMessageName == "" {
			logrus.Fatal("Configuration field oidc.spoe_message is not defined")
		}

		var clientsStore auth.OIDCClientsStore

		// TODO: watch the config file to update the list of clients dynamically
		var clientsConfig map[string]auth.OIDCClientConfig
		err := viper.UnmarshalKey("oidc.clients", &clientsConfig)
		if err != nil {
			logrus.Panic(err)
		}
		clientsStore = auth.NewStaticOIDCClientStore(clientsConfig)

		// Load Cookie and State TTLs and set defaults.
		var (
			cookieTTL time.Duration
			stateTTL  time.Duration
		)

		if v := viper.GetUint64("oidc.cookie_ttl_seconds"); v != 0 {
			cookieTTL = time.Duration(v) * time.Second
		}

		if v := viper.GetUint64("oidc.state_ttl_seconds"); v != 0 {
			stateTTL = time.Duration(v) * time.Second
		} else {
			stateTTL = DefaultStateTTL
		}

		oidcAuthConfig := auth.OIDCAuthenticatorOptions{
			OAuth2AuthenticatorOptions: auth.OAuth2AuthenticatorOptions{
				RedirectCallbackPath:       viper.GetString("oidc.oauth2_callback_path"),
				LogoutPath:                 viper.GetString("oidc.oauth2_logout_path"),
				HealthCheckPath:            viper.GetString("oidc.oauth2_healthcheck_path"),
				CallbackAddr:               viper.GetString("oidc.callback_addr"),
				CookieName:                 viper.GetString("oidc.cookie_name"),
				CookieSecure:               viper.GetBool("oidc.cookie_secure"),
				CookieTTL:                  cookieTTL,
				StateTTL:                   stateTTL,
				SignatureSecret:            viper.GetString("oidc.signature_secret"),
				SupportEmailAddress:        viper.GetString("oidc.server.contacts.email"),
				SupportEmailSubject:        viper.GetString("oidc.server.contacts.subject"),
				ClientsStore:               clientsStore,
				ReadClientInfoFromMessages: flagsCfg.dynamicClientInfo,
			},
			ProviderURL:      viper.GetString("oidc.provider_url"),
			EncryptionSecret: viper.GetString("oidc.encryption_secret"),
		}

		oidcAuthenticator := auth.NewOIDCAuthenticator(oidcAuthConfig)
		authenticators[SPOEMessageName] = oidcAuthenticator

		// Print configuration.
		logrus.WithFields(logrus.Fields{
			"authenticator":           "OAuth2",
			"SPOE_message":            SPOEMessageName,
			"oauth2_callback_path":    oidcAuthConfig.RedirectCallbackPath,
			"oauth2_logout_path":      oidcAuthConfig.LogoutPath,
			"oauth2_healthcheck_path": oidcAuthConfig.HealthCheckPath,
			"callback_addr":           oidcAuthConfig.CallbackAddr,
			"cookie_name":             oidcAuthConfig.CookieName,
			"cookie_secure":           oidcAuthConfig.CookieSecure,
			"cookie_ttl_seconds":      oidcAuthConfig.CookieTTL.Seconds(),
			"state_ttl_seconds":       oidcAuthConfig.StateTTL.Seconds(),
			"dynamic_client_info":     oidcAuthConfig.ReadClientInfoFromMessages,
			"provider_url":            oidcAuthConfig.ProviderURL,
			"support_email_address":   oidcAuthConfig.SupportEmailAddress,
			"support_email_subject":   oidcAuthConfig.SupportEmailSubject,
		}).Info("OAuth2 authenticator configuration")

		var clientsLog = logrus.WithFields(logrus.Fields{
			"authenticator": "OAuth2",
			"message_type":  "client_info",
		})
		for k, v := range clientsConfig {
			clientsLog.WithFields(logrus.Fields{
				"client_domain": k,
				"client_id":     v.ClientID,
				"redirect_url":  v.RedirectURL,
			}).Info("OAuth2 static client configuration")
		}
	} else {
		logrus.WithField("authenticator", "OAuth2").Info("OAuth2 authentication is not configured")
	}

	// Starting profiler.
	if flagsCfg.pprofBind != "" {
		go func() {
			logrus.WithField("listen_socket", flagsCfg.pprofBind).Info("Starting pprof server")

			if err := http.ListenAndServe(flagsCfg.pprofBind, nil); err != nil {
				logrus.WithError(err).Fatal("Can not start pprof server")
			}

			logrus.Info("Stopped pprof server")
		}()
	}

	agent.StartAgent(viper.GetString("server.addr"), authenticators)
}
