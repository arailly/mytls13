package appdata

import "github.com/arailly/mytls13/record"

const (
	contentTypeApplicationData uint8 = 23
)

func Send(conn *record.Conn, b []byte) {
	conn.Push(contentTypeApplicationData, b)
	conn.Flush()
}
