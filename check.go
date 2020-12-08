package pscan

import (
	"net"
	"strconv"
	"time"
)

func CheckPort(ip string, port int, timeout time.Duration) bool {
	conn, err := net.DialTimeout(`tcp`, ip+`:`+strconv.Itoa(port), timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	return true
}
