# LDAP Authentication

## Building & running

    go get ./...
    go build -o haproxy-spoe-ldap cmd/haproxy-spoe-ldap/main.go

    # Check the usage of the command to configure against your AD
    ./haproxy-spoe-ldap --help

    # For example
    ./haproxy-spoe-ldap -addr :8081 -ldap-url ldap -ldap-userdn cn=admin,dc=example,dc=com -ldap-password password -ldap-base-dn dc=example,dc=com -ldap-user-filter "(cn={login})"


## TODO

This agent is currently experimental and under active development. I would not advise to run it in
production yet unless you know what you're doing.

* Create a pool of reusable connections to the LDAP server(s).
* Create a cache of authenticated users with a TTL to avoid validating every queries against the LDAP server.
* Avoid the search query when binding the user against the LDAP server.