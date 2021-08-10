# LDAP Authentication

## TODO

This agent is currently experimental and under active development. I would not advise to run it in
production yet unless you know what you're doing.

* Create a pool of reusable connections to the LDAP server(s).
* Create a cache of authenticated users with a TTL to avoid validating every queries against the LDAP server.
* Avoid the search query when binding the user against the LDAP server.