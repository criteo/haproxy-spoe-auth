# HAProxy SPOE Authentication

![Build & Test](https://github.com/criteo/haproxy-spoe-auth/workflows/Build%20&%20Test/badge.svg)

This project is a an agent allowing HAProxy to to handle authentication requests.

## Test it now!

The agent is packaged in a docker-compose for you to quickly test it. You need to make sure
Docker and docker-compose is installed on your machine. Also make sure that port 9080 is
available.

Now, add the two following lines to your /etc/hosts to fake the domains:

    127.0.0.1       unprotected.example.com
    127.0.0.1       protected-ldap.example.com
    127.0.0.1       protected-oidc.example.com
    127.0.0.1       auth.example.com  # Used for the redirect callback ending the OAuth2 transaction
    127.0.0.1       dex.example.com   # An OIDC server implementation

And then run

    docker-compose up -d

Now you can test the following commands

    # This a public domain
    curl http://unprotected.example.com:9080/

    # This domain is protected but no credentials are provided, it should return 401.
    curl http://protected-ldap.example.com:9080/

    # This domain is protected and credentials are provided, it should return 200.
    curl -u "john:password" http://protected-ldap.example.com:9080/

    # This domain is protected and credentials are provided but with a bad password, it should return 401.
    curl -u "john:badpassword" http://protected-ldap.example.com:9080/

    # This domain is protected by OpenID Connect and credentials are provided, it should return 200.
    Visit http://protected-oidc.example.com:9080/ in a browser

Trying to visit the website protected by LDAP in a browser will display a basic auth form that you should fill
before being granted the rights to visit the page. With OpenID Connect, you should be redirected to the Dex
authentication portal to complete the authentication process.

The users available in the LDAP are stored in the file [resources/ldap/base.ldif](./resources/ldap/01-base.ldif).

## Deployment

The agent should be deployed on the same host than the HAProxy to give the best performance.

Then you can check the configuration of HAProxy and the SPOE agents available under [resources/haproxy](./resources/haproxy)

## Architecture

The agent communicates with HAProxy leveraging the Stream Processing Offload Engine (SPOE) feature
of HAProxy documented here: https://github.com/haproxy/haproxy/blob/master/doc/SPOE.txt.

This features allows a bi-directional communication between the agent and HAProxy allowing HAProxy
to forward requests requiring authentication to the agent which itself validates the credentials
against a LDAP server.

### LDAP

Please see the [dedicated section](./docs/ldap.md).

### OpenID Connect

Please see the [dedicated section](./docs/openidconnect.md).

## License

This project is licensed under the Apache 2.0 license. The terms of the license are detailed in LICENSE.
