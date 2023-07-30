package alert

import "github.com/arailly/mytls13/record"

const (
	contentTypeAlert uint8 = 21

	alertLevelWarning uint8 = 1
	alertLevelFatal   uint8 = 2

	AlertDescCloseNotify uint8 = 0
)

func Send(conn *record.Conn, alertDesc uint8) error {
	conn.Push(contentTypeAlert, []byte{alertLevelWarning, alertDesc})
	return conn.Flush()
}
