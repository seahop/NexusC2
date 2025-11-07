// Add to internal/agent/socks/socks_client.go
package socks

import (
	"log"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

type Client struct {
	conn        *ssh.Client
	credentials *Credentials
}

func NewClient(addr string, path string, creds *Credentials) (*Client, error) {
	config := &ssh.ClientConfig{
		User: creds.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(creds.Password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	if signer := parsePrivateKey(creds.SSHKey); signer != nil {
		config.Auth = append(config.Auth, ssh.PublicKeys(signer))
	}

	// Connect via WSS
	conn, err := dialWSS(addr, path)
	if err != nil {
		return nil, err
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, "", config)
	if err != nil {
		conn.Close()
		return nil, err
	}

	// Add SSH keepalive
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			_, _, err := sshConn.SendRequest("keepalive@golang.org", true, nil)
			if err != nil {
				log.Printf("[ERROR] Failed to send SSH keepalive: %v", err)
				return
			}
			log.Printf("[DEBUG] Sent SSH keepalive")
		}
	}()

	client := ssh.NewClient(sshConn, chans, reqs)
	return &Client{
		conn:        client,
		credentials: creds,
	}, nil
}

func (c *Client) Listen(network, addr string) (net.Listener, error) {
	return c.conn.Listen(network, addr)
}

func (c *Client) Dial(network, addr string) (net.Conn, error) {
	return c.conn.Dial(network, addr)
}

func (c *Client) Close() error {
	return c.conn.Close()
}
