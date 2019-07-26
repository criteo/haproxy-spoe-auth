# HAProxy LDAP Authentication Forwarder

This project is a an agent allowing HAProxy to forward authentication requests to a LDAP server.

## Test it now!

The agent is packaged in a docker-compose for you to quickly test it. You need to make sure
Docker and docker-compose is installed on your machine. Also make sure that port 9080 is
available.

Now, add the two following lines to your /etc/hosts to fake the domains:

    127.0.0.1       protected.example.com
    127.0.0.1       unprotected.example.com

And then run

    docker-compose up -d

Now you can test the following commands

    # This a public domain
    curl http://unprotected.example.com:9080/

    # This domain is protected but no credentials are provided, it should return 401.
    curl http://protected.example.com:9080/

    # This domain is protected and credentials are provided, it should return 200.
    curl -u "john:password" http://protected.example.com:9080/

    # This domain is protected and credentials are provided but with a bad password, it should return 401.
    curl -u "john:badpassword" http://protected.example.com:9080/

Trying to visit the protected website in a browser will display a basic auth form that you should fill
before being granted the rights to visit the page.

The users available in the LDAP are stored in the file `resources/ldap/base.ldif`.

## Deployment

The agent should be deployed on the same host than the HAProxy to give the best performances.

Then here are examples of configuration that you can use to run the agent

    # haproxy.conf

    ...

    frontend haproxynode
        bind *:80
        mode http

        acl protected_domain hdr_beg(host) -i protected.example.com

        filter spoe engine ldap-auth config /usr/local/etc/haproxy/spoe-ldap-auth.conf
        acl authenticated var(sess.auth.is_authenticated) -m bool

        use_backend protected-app-backend if authenticated protected_domain
        use_backend unauthorized-backend if ! authenticated protected_domain

        default_backend unprotected-app-backend

    backend unprotected-app-backend
        mode http
        balance roundrobin
        server node-unprotected-app unprotected-backend:80 check

    backend protected-app-backend
        mode http
        balance roundrobin

        server node-protected-app protected-backend:80 check

    backend unauthorized-backend
        mode http
        balance roundrobin
        http-response set-status 401
        http-response add-header WWW-Authenticate 'Basic realm="Access the webapp"'

        server node-noauth unauthorized-backend:80 check

    ...

And the configuration of the agent is as follows

    # spoe-ldap-auth.conf

    [ldap-auth]
    spoe-agent auth-agents
        messages try-auth

        option var-prefix auth
        option  async

        timeout hello      2s
        timeout idle       2m
        timeout processing 1s

        use-backend auth-backend

    spoe-message try-auth
        args authorization=req.hdr(Authorization)
        event on-frontend-http-request if { hdr_beg(host) -i protected.example.com }


## Architecture

The agent communicates with HAProxy leveraging the Stream Processing Offload Engine (SPOE) feature
of HAProxy documented here: https://github.com/haproxy/haproxy/blob/master/doc/SPOE.txt.

This features allows a bi-directional communication between the agent and HAProxy allowing HAProxy
to forward requests requiring authentication to the agent which itself validates the credentials
against a LDAP server.

## Performance

The agent is written in Go allowing to set performance expectations pretty high. The target objective is
clearly to remove any allocation on the hot path to make the agent as efficient as possible and completely
avoid garbage collection.

Also, one must take care of the HAProxy configuration when using the agent. The example provided in this
repository allows to split the domains into two categories: the public domains and the ones requiring authentication.
If correctly configured, only domains requiring authentication will trigger a call to the agent hence keeping the
raw performance for public domains. The trick is the condition in the `try-auth` message in the spoe configuration.

    event on-frontend-http-request if { hdr_beg(host) -i protected.example.com }


## Building & running

    go get ./...
    go build

    ./haproxy-ldap-auth --help

## TODO

This agent is currently experimental and under active development. I would not advise to run it in
production yet unless you know what you're doing.

* Create a pool of reusable connections to the LDAP server(s).
* Create a cache of authenticated users with a TTL to avoid validating every queries against the LDAP server.
* Allow to skip the search query when binding the user against the LDAP server.