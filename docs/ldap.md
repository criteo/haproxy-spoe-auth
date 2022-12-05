# LDAP Authentication

The following spoa message string will be replaced in ldap search query, when provided
    - {user}; represent the user to match
    - {group}: represent the group to which belongs the user
An example of user query is provided, but has to be adapated following the LDAP implementation.

## TODO

This agent is currently experimental and under active development. I would not advise to run it in
production yet unless you know what you're doing.

* Create a pool of reusable connections to the LDAP server(s).
* Create a cache of authenticated users with a TTL to avoid validating every queries against the LDAP server.
* Avoid the search query when binding the user against the LDAP server.
