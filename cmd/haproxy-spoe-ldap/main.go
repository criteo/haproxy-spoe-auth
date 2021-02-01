package main

import (
	"flag"

	"github.com/clems4ever/haproxy-spoe-auth/internal/agent"
	"github.com/clems4ever/haproxy-spoe-auth/internal/auth"
)

func main() {
	interfaceAddrPtr := flag.String("addr", ":8081", "The port of the agent")

	ldapUserDNPtr := flag.String("ldap-userdn", "", "The username to connect to LDAP to perform search queries")
	ldapPasswordPtr := flag.String("ldap-password", "", "The password of the user connecting to the LDAP to perform search queries")
	ldapURLPtr := flag.String("ldap-url", "", "The URL to the LDAP server")
	ldapBasePtr := flag.String("ldap-base-dn", "", "The base DN from where to look for users")
	ldapUserFilterPtr := flag.String("ldap-user-filter", "(cn={})", "The filter used to find user in LDAP server")
	ldapPortPtr := flag.Int("ldap-port", 389, "The port of the LDAP server")

	flag.Parse()

	if ldapUserDNPtr == nil || (ldapUserDNPtr != nil && *ldapUserDNPtr == "") {
		flag.PrintDefaults()
		return
	}

	if ldapPasswordPtr == nil || (ldapPasswordPtr != nil && *ldapPasswordPtr == "") {
		flag.PrintDefaults()
		return
	}

	if ldapURLPtr == nil || (ldapURLPtr != nil && *ldapURLPtr == "") {
		flag.PrintDefaults()
		return
	}

	if ldapBasePtr == nil || (ldapBasePtr != nil && *ldapBasePtr == "") {
		flag.PrintDefaults()
		return
	}

	ldapAauthentifier := auth.NewLDAPAuthentifier(auth.LDAPConnectionDetails{
		Hostname:   *ldapURLPtr,
		UserDN:     *ldapUserDNPtr,
		Password:   *ldapPasswordPtr,
		BaseDN:     *ldapBasePtr,
		UserFilter: *ldapUserFilterPtr,
		Port:       *ldapPortPtr,
	})

	agent.StartAgent(*interfaceAddrPtr, ldapAauthentifier)
}
