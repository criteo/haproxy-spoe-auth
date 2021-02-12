package agent

import (
	"log"

	"github.com/clems4ever/haproxy-spoe-auth/internal/auth"
	spoe "github.com/criteo/haproxy-spoe-go"
	"github.com/sirupsen/logrus"
)

func init() {
	logrus.SetLevel(logrus.DebugLevel)
}

// StartAgent start the agent
func StartAgent(interfaceAddr string, authentifier auth.Authenticator) {
	agent := spoe.New(func(messages *spoe.MessageIterator) ([]spoe.Action, error) {
		var actions []spoe.Action
		for messages.Next() {
			msg := messages.Message
			logrus.Debugf("New message with name %s received", msg.Name)

			if msg.Name != "try-auth" {
				continue
			}

			a, err := authentifier.Authenticate(&msg)
			if err != nil {
				logrus.Errorf("Unable to treat request: %v", err)
				continue
			}

			actions = append(actions, a...)
		}

		return actions, nil
	})

	logrus.Infof("Agent starting and listening on %s", interfaceAddr)
	if err := agent.ListenAndServe(interfaceAddr); err != nil {
		log.Fatal(err)
	}
}
