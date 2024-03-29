package mytls

import (
	"strings"

	core "github.com/arailly/mytls13"
	"github.com/arailly/mytls13/alert"
	"github.com/arailly/mytls13/appdata"
	"github.com/arailly/mytls13/handshake"
	"github.com/arailly/mytls13/record"
)

type Conn struct {
	conn *record.Conn
}

func Dial(
	network string,
	addr string,
	config *core.Config,
) (*Conn, error) {
	conn, err := record.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	if config.ServerName == "" {
		if addr[:4] == "[::]" {
			config.ServerName = "127.0.0.1"
		} else {
			config.ServerName = strings.Split(addr, ":")[0]
		}
	}
	if err := handshake.StartHandshake(conn, config); err != nil {
		return nil, err
	}
	return &Conn{
		conn,
	}, nil
}

type Listener struct {
	l      *record.Listener
	config *core.Config
}

func Listen(
	network string,
	addr string,
	config *core.Config,
) (
	*Listener,
	error,
) {
	l, err := record.Listen(network, addr)
	if err != nil {
		return nil, err
	}
	return &Listener{l, config}, err
}

func (l *Listener) Accept() (*Conn, error) {
	conn, err := l.l.Accept()
	if err != nil {
		return nil, err
	}
	handshake.RespondHandshake(conn, l.config)
	return &Conn{conn}, nil
}

func (l *Listener) Addr() string {
	return l.l.Addr()
}

func (c *Conn) Read(b []byte) (int, error) {
	n, err := c.conn.Read(b)
	if err != nil {
		return 0, err
	}
	return n, nil
}

func (c *Conn) Send(b []byte) error {
	appdata.Send(c.conn, b)
	return c.conn.Flush()
}

func (c *Conn) Close() error {
	err := alert.Send(c.conn, alert.AlertDescCloseNotify)
	if err != nil {
		return err
	}
	return c.conn.Close()
}
