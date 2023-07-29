package record

import (
	"io"
	"net"
	"time"

	"github.com/arailly/mytls13/key"
	"github.com/arailly/mytls13/util"
)

func Dial(network string, addr string) (*Conn, error) {
	conn, err := net.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	return &Conn{
		netConn: conn,
		state:   &state{},
		Keys:    key.NewKeys("client"),
	}, nil
}

func Listen(network string, addr string) (*Listener, error) {
	l, err := net.Listen(network, addr)
	if err != nil {
		return nil, err
	}
	return &Listener{l}, nil
}

type Listener struct {
	netListener net.Listener
}

func (l *Listener) Accept() (*Conn, error) {
	conn, err := l.netListener.Accept()
	if err != nil {
		return nil, err
	}
	return &Conn{
		netConn: conn,
		state:   &state{},
		Keys:    key.NewKeys("server"),
	}, nil
}

func (l *Listener) Addr() string {
	return l.netListener.Addr().String()
}

func (l *Listener) Close() error {
	return l.netListener.Close()
}

type state struct {
	writeSeqNum uint64
	readSeqNum  uint64
	cipherRead  bool
	cipherWrite bool
}

type Conn struct {
	netConn net.Conn
	state   *state
	Keys    *key.Keys

	sendBuf []byte
	recvBuf []byte
}

func (c *Conn) Close() {
	c.netConn.Close()
}

func (c *Conn) StartCipherRead() {
	c.state.cipherRead = true
}

func (c *Conn) StartCipherWrite() {
	c.state.cipherWrite = true
}

func (c *Conn) incrementReadSeqNum() {
	c.state.readSeqNum++
}

func (c *Conn) ResetReadSeqNum() {
	c.state.readSeqNum = 0
}

func (c *Conn) IncrementWriteSeqNum() {
	c.state.writeSeqNum++
}

func (c *Conn) ResetWriteSeqNum() {
	c.state.writeSeqNum = 0
}

func (c *Conn) Flush() error {
	_, err := c.netConn.Write(c.sendBuf)
	if err != nil {
		return err
	}
	c.sendBuf = make([]byte, 0)
	return nil
}

func (c *Conn) Push(
	contentType uint8,
	data []byte,
) error {
	var record []byte
	if !c.state.cipherWrite {
		record = util.ToBytes(newTLSPlainText(contentType, data))
	} else {
		plaintext := util.ToBytes(tlsInnerPlaintext{
			content:     data,
			contentType: contentType,
		})
		encrypted, err := encrypt(
			c.Keys.WriteKey,
			c.Keys.WriteIV,
			c.state.writeSeqNum,
			plaintext,
		)
		if err != nil {
			return err
		}
		record = util.ToBytes(newTLSCipherText(encrypted))
	}
	c.sendBuf = append(c.sendBuf, record...)
	return nil
}

func (c *Conn) Read(b []byte) (int, error) {
	if len(b) <= len(c.recvBuf) {
		length := copy(b, c.recvBuf)
		c.recvBuf = c.recvBuf[length:]
		return length, nil
	}
	header := make([]byte, 5)
	n, err := c.netConn.Read(header)
	if n == 0 && err == io.EOF {
		length := copy(b, c.recvBuf)
		c.recvBuf = make([]byte, 0)
		return length, nil
	}
	if n != 5 {
		panic("read record error")
	}
	length := int(util.ToUint16(header[3:5]))
	for {
		fragment := make([]byte, 0)
		for i := 0; i < length; i++ {
			f := make([]byte, 1)
			_, err := c.netConn.Read(f)
			if err != nil {
				return 0, err
			}
			fragment = append(fragment, f...)
		}

		if !c.state.cipherRead {
			c.recvBuf = append(c.recvBuf, fragment...)
		} else {
			decrypted, err := decrypt(
				c.Keys.ReadKey,
				c.Keys.ReadIV,
				c.state.readSeqNum,
				fragment,
			)
			c.incrementReadSeqNum()
			if err != nil {
				return 0, err
			}
			c.recvBuf = append(c.recvBuf, decrypted...)
		}
		if len(c.recvBuf) >= len(b) {
			break
		}
		time.Sleep(time.Microsecond)
	}
	length = copy(b, c.recvBuf)
	c.recvBuf = c.recvBuf[length:]
	return length, nil
}
