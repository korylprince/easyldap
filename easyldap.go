package easyldap

import (
	"log"

	"gopkg.in/ldap.v2"
)

func getCookie(cntls []ldap.Control) []byte {
	for _, c := range cntls {
		if p, ok := c.(*ldap.ControlPaging); ok {
			return p.Cookie
		}
	}
	return nil
}

//Query returns all the entries matching the configuration given in c
func Query(c *Config) ([]*ldap.Entry, error) {

	conn, err := Connect(c)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	return QueryWithConn(c, conn)
}

//QueryWithConn returns all the entries matching the configuration given in c, using the given connection
func QueryWithConn(c *Config, conn *ldap.Conn) ([]*ldap.Entry, error) {
	err := conn.Bind(c.Username, c.Password)
	if err != nil {
		if c.Debug {
			log.Printf("DEBUG: LDAP Error %v\n", err)
		}
		return nil, err
	}

	var entries []*ldap.Entry

	cntls := []ldap.Control{
		&ldap.ControlPaging{
			PagingSize: uint32(c.PagingSize),
		},
	}

	for {
		search := &ldap.SearchRequest{
			BaseDN:       c.BaseDN,
			Scope:        ldap.ScopeWholeSubtree,
			DerefAliases: ldap.NeverDerefAliases,
			SizeLimit:    c.PagingSize,
			TimeLimit:    0,
			TypesOnly:    false,
			Filter:       c.Filter,
			Attributes:   c.Attributes,
			Controls:     cntls,
		}

		res, err := conn.Search(search)
		if err != nil {
			if c.Debug {
				log.Printf("DEBUG: LDAP Error %v\n", err)
			}
			return nil, err
		}

		entries = append(entries, res.Entries...)

		cookie := getCookie(res.Controls)
		if cookie == nil {
			break
		}

		cntls = []ldap.Control{
			&ldap.ControlPaging{
				PagingSize: uint32(c.PagingSize),
				Cookie:     cookie,
			},
		}
	}
	return entries, nil
}
