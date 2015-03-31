package easyldap

//Connect returns an open connection to an Active Directory server specified by the given config
import (
	"crypto/tls"
	"fmt"
	"log"

	"gopkg.in/ldap.v1"
)

//SecurityType specifies how to connect to an Active Directory server
type SecurityType int

//Security will default to SecurityNone if not given.
const (
	SecurityNone SecurityType = iota
	SecurityTLS
	SecurityStartTLS
)

//Connect returns an ldap.Conn with the given Config
func Connect(c *Config) (*ldap.Conn, error) {
	if c.TLSConfig == nil {
		c.TLSConfig = &tls.Config{
			ServerName: c.Server,
		}
	}

	var (
		conn *ldap.Conn
		err  error
	)

	switch c.Security {
	case SecurityNone:
		conn, err = ldap.Dial("tcp", fmt.Sprintf("%s:%d", c.Server, c.Port))
		if err != nil {
			if c.Debug {
				log.Printf("DEBUG: LDAP Error %v\n", err)
			}
			return nil, err
		}
	case SecurityTLS:
		conn, err = ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", c.Server, c.Port), c.TLSConfig)
		if err != nil {
			if c.Debug {
				log.Printf("DEBUG: LDAP Error %v\n", err)
			}
			return nil, err
		}
	case SecurityStartTLS:
		conn, err = ldap.Dial("tcp", fmt.Sprintf("%s:%d", c.Server, c.Port))
		if err != nil {
			if c.Debug {
				log.Printf("DEBUG: LDAP Error %v\n", err)
			}
			return nil, err
		}
		err = conn.StartTLS(c.TLSConfig)
		if err != nil {
			if c.Debug {
				log.Printf("DEBUG: LDAP Error %v\n", err)
			}
			return nil, err
		}
	default:
		return nil, ConfigError("Invalid Security setting")
	}
	if c.Debug {
		conn.Debug = true
	}
	return conn, nil
}
