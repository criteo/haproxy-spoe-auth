# Configuration

## Performance: Filter Bypass

The agent is written in Go allowing to set performance expectations pretty high.

Also, one must take care of the HAProxy configuration when using the agent. The example provided in this
repository allows to split the domains into two categories: the public domains and the ones requiring authentication.
If correctly configured, only domains requiring authentication will trigger a call to the agent hence keeping the
raw performance for public domains. The trick is the condition in the `try-auth` message in the spoe configuration.

    event on-frontend-http-request if { hdr_beg(host) -i protected.example.com }


