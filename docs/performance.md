# Performance Optimization

## Filter Bypass

The agent is written in Go allowing to set performance expectations pretty high.

Also, one must take care of the HAProxy configuration when using the agent. The example provided in this
repository allows to split the domains into two categories: the public domains and the ones requiring authentication.
If correctly configured, only domains requiring authentication will trigger a call to the agent hence keeping the
raw performance for public domains. The trick is the condition in the `try-auth` message in the spoe configuration.

    event on-frontend-http-request if { hdr_beg(host) -i app1.example.com } || { hdr_beg(host) -i app2.example.com }

One can also use a map instead of logical operators if the number of domains becomes too big (https://www.haproxy.com/blog/introduction-to-haproxy-maps/).
