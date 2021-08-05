package agent

import (
	"log"

	"github.com/criteo/haproxy-spoe-auth/internal/auth"
	spoe "github.com/criteo/haproxy-spoe-go"
	"github.com/sirupsen/logrus"
)

// NotAuthenticatedMessage SPOE response stating the user is not authenticated
var NotAuthenticatedMessage = spoe.ActionSetVar{
	Name:  "is_authenticated",
	Scope: spoe.VarScopeSession,
	Value: false,
}

// AuthenticatedMessage SPOE response stating the user is authenticated
var AuthenticatedMessage = spoe.ActionSetVar{
	Name:  "is_authenticated",
	Scope: spoe.VarScopeSession,
	Value: true,
}

// StartAgent start the agent
func StartAgent(interfaceAddr string, authentifiers map[string]auth.Authenticator) {
	agent := spoe.New(func(messages *spoe.MessageIterator) ([]spoe.Action, error) {
		var actions []spoe.Action

		var authenticated bool = false
		for messages.Next() {
			msg := messages.Message
			logrus.Debugf("New message with name %s received", msg.Name)

			authentifier, ok := authentifiers[msg.Name]
			if ok {
				isAuthenticated, replyActions, err := authentifier.Authenticate(&msg)
				if err != nil {
					logrus.Errorf("Unable to authenticate user: %v", err)
					continue
				}
				actions = append(actions, replyActions...)

				if isAuthenticated {
					authenticated = true
				}
			}
		}

		if authenticated {
			actions = append(actions, AuthenticatedMessage)
		} else {
			actions = append(actions, NotAuthenticatedMessage)
		}

		return actions, nil
	})

	logrus.Infof("Agent starting and listening on %s", interfaceAddr)
	if err := agent.ListenAndServe(interfaceAddr); err != nil {
		log.Fatal(err)
	}
}
