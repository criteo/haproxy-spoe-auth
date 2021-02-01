package agent

import (
	"log"

	"github.com/clems4ever/haproxy-spoe-auth/internal/auth"
	spoe "github.com/criteo/haproxy-spoe-go"
	"github.com/sirupsen/logrus"
)

// StartAgent start the agent
func StartAgent(interfaceAddr string, authentifier auth.Authenticator) {
	agent := spoe.New(func(messages *spoe.MessageIterator) ([]spoe.Action, error) {
		authenticated := false
		for messages.Next() {
			msg := messages.Message
			logrus.Debugf("New message with name %s received", msg.Name)

			if msg.Name != "try-auth" {
				continue
			}

			if err := authentifier.Authenticate(&msg); err != nil {
				logrus.Errorf("Unable to authenticate request: %v", err)
				continue
			}

			authenticated = true
		}

		return []spoe.Action{
			spoe.ActionSetVar{
				Name:  "is_authenticated",
				Scope: spoe.VarScopeSession,
				Value: authenticated,
			},
		}, nil
	})

	logrus.Infof("Agent starting and listening on %s", interfaceAddr)
	if err := agent.ListenAndServe(interfaceAddr); err != nil {
		log.Fatal(err)
	}
}
