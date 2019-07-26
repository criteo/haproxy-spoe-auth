# HAProxy LDAP Authentication Forwarder

This project is a an agent allowing HAProxy to forward authentication requests to a LDAP server.

## Architecture

The agent communicates with HAProxy leveraging the Stream Processing Offload Engine (SPOE) feature
of HAProxy documented here: https://github.com/haproxy/haproxy/blob/master/doc/SPOE.txt.

This features allow a bi-directional communication between the agent and HAProxy allowing HAProxy
to forward requests requiring authentication to the agent which itself validates the credentials
against a LDAP server.


## TODO

This agent is currently experimental and under active development. I would not advise to run it in
production yet unless you know what you're doing.

* Create a pool of reusable connections to the LDAP server(s).
* Create a cache of authenticated users with a TTL to avoid validating every queries against the LDAP server.
* Allow to skip the search query when binding the user against the LDAP server.