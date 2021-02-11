# OpenID Connect Authentication

## Building & running

    go get ./...
    go build -o haproxy-spoe-oidc cmd/haproxy-spoe-oidc/main.go

    # Check the usage of the command to configure against your AD
    ./haproxy-spoe-oidc --help

    # For example
    ./haproxy-spoe-oidc -addr :8081 -oidc-provider http://dex.example.com:9080/dex -client-id haproxy-auth -client-secret haproxy-auth-secret -redirect-url http://auth.example.com:9080/oauth2/callback -callback-addr :5000 -cookie-name authsession -cookie-domain example.com -cookie-unsecure -signature-secret myunsecuresecret -encryption-secret anotherunsecuresecret


## Architecture

The SPOE agent receives authentication request messages when a request is made on the protected endpoint. Either this
request comes without a session cookie or with one previously provided after authentication.

If the request comes without, the agent sign the original URL and redirects the user to the OpenID Connect server to
perform the authentication workflow with the signed original URL stored in the state. Once the authentication is done,
the server redirects back to the callback URL exposed by the SPOE agent on a different port than the one for the SPOE communication. The API serves '/oauth2/callback' and '/logout' only.

When the user comes back to the callback endpoint, the OpenID Connect ID token is retrieved, encrypted, set into
the cookie covering the top domain and sent along with an HTML response triggering a redirection to the target URL
on the client side.

Now the client's browser stores that cookie and it is transmitted with each request to the service. This value is decrypted and the ID token is verified by the agent before approving or denying the request.


This workflow is presented in two diagrams: [architecture](./images/architecture-oidc.png) and [sequence](./images/sequence-oidc.png)

## Design Decisions

### Session management

The SPOE agent permits authentication and the requirement was that it should be stateless. Therefore, the session is
maintained by encrypting the ID Token returned by the OIDC provider and setting it in a httpOnly cookie.

The decision to store the ID token in the cookie is also considered a security measure to not rely solely on the
server hosting the SPOE agent to ensure the security of the session. Indeed, to attack the whole session system, the
attacker need to have access to the secret to encrypt the cookie but also to the key signing the ID token. Let say the
attacker gets access to the encryption key, only confidentiality is broken.

### ID Token encryption

The ID token is encrypted with AES-GCM-256. This means that we maintain confidentiality and the message is also
authenticated thanks to the GCM mode of operation.

### Session storage

There is no bullet proof way of storing sessions, each one comes with its own set of pros/cons. However, we want the
system to be generic and so it must not imply any modification from the client code to work.

#### httpOnly cookie

Cookies are made for storing sessions. We know that there are many XSS threats related to cookie leaks so that's
why setting the httpOnly cookie reduces the risk by making sure JS should not have access to the cookie. However,
we should keep in mind that some browsers might not implement httpOnly but cookie is the only way to transport the
ID without modification of the code.

#### LocalStorage

The session could be stored in local storage but this requires the application to support it. Plus, putting secrets in
the local storage is usually not recommended since there is no mechanism to prevent XSS to leak the token.

#### Memory

Memory is probably the safest way to store the information but it has downsides if working with websites with multiple
pages as the secret must be kept between page loads somehow. However, XSS might be more complex to implement than just reading a store.

### Signing of the origin URL

The user being redirected after a successful authentication workflow is exposed to open redirect vulnerability. To
prevent such a threat, the original URL provided by HAProxy is signed by the agent before being transmitted in the
state during the OAuth2 transaction. It is then verified at the end of the workflow to allow or deny the redirection.
That way, it's impossible for hackers to craft a URL to redirect the user to.

### Cookie are secure by default

Cookies are secure by default. There is an option to disable that flag but please make sure about what you do if you
disable the flag. It would expose your users' sessions to leakage on the Internet. This flag is only here for test
purposes.

### Cookie TTL

The cookie has a TTL set to 1h by default. This is the amount of time before the user does a new round trip to the
OAuth2 server. If the server has kept the user logged in, there will be no authentication involved but the user will be
redirected. You need to find the right balance between longevity of the session and security. The more the session lives,
the more there are chances the session has been compromised.


## TODO

* Add a mechanism to denylist a token.
* Allow the SPOE agent to match a certain list of groups the user belongs to.
* Think about secret rotation.
* Prevent replay attacks by putting some kind of nonce in the state.