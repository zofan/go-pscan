package pscan

import (
	"net"
)

func IsExternalIP4(ip net.IP) bool {
	if !ip.IsGlobalUnicast() {
		return false
	}

	if ip4 := ip.To4(); ip4 != nil {
		switch {
		case ip4[0] == 10:
			return false
		case ip4[0] == 127:
			return false
		case ip4[0] == 240: // reserved
			return false
		case ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31:
			return false
		case ip4[0] == 192 && ip4[1] == 168:
			return false
		case ip4[0] == 169 && ip4[1] == 254:
			return false
		}
	}

	return true
}
