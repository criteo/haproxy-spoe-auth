# Configuration

The agent is configured through a configuration file provided as argument of the command.
An example configuration file can be found [here](../resources/configuration/config.yml).

One can run the application with the following command but beware the configuration depends on other components otherwise deployed with docker-compose as described in the [README](../README.md).

    $ go run cmd/haproxy-spoe-auth/main.go -config resources/configuration/config.yml

The options available in the configuration file are detailed in the file.