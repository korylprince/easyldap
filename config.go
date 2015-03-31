package easyldap

import "crypto/tls"

//ConfigError is an error resulting from a bad Config
type ConfigError string

func (c ConfigError) Error() string {
	return string(c)
}

//Config contains all the information to connect and query an ldap server
type Config struct {
	Server     string
	Port       int
	BaseDN     string
	Security   SecurityType
	TLSConfig  *tls.Config
	PagingSize int
	Filter     string
	Attributes []string
	Username   string
	Password   string
	Debug      bool
}
