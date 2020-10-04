package pscan

import (
	"encoding/binary"
	"math"
	"net"
	"strconv"
	"sync"
	"time"
)

type IpRange struct {
	Start   string
	End     string
	Workers int
}

type PortRange struct {
	Start int
	End   int
	List  []int
}

type Result struct {
	IP   net.IP
	Port int
}

func ScanIP(ip string, pr PortRange, timeout time.Duration) []int {
	var result []int

	for _, p := range pr.List {
		if CheckPort(ip, p, timeout) {
			result = append(result, p)
		}
	}

	if pr.Start > 0 && pr.End <= math.MaxUint16 && pr.Start < pr.End {
		for p := pr.Start; p <= pr.End; p++ {
			if CheckPort(ip, p, timeout) {
				result = append(result, p)
			}
		}
	}

	return result
}

//func ScanIpRange(ipr IpRange, pr PortRange, rCh chan Result) {
//	DoIpRange(ipr, func(ip net.IP) {
//		for _, p := range ScanIP(ip.String(), pr, ipr.Timeout) {
//			rCh <- Result{ip, p}
//		}
//	})
//}

func DoIpRange(ipr IpRange, fn func(ip net.IP)) {
	wg := &sync.WaitGroup{}

	sl := binary.BigEndian.Uint32(net.ParseIP(ipr.Start).To4())
	el := binary.BigEndian.Uint32(net.ParseIP(ipr.End).To4())

	step := (el - sl) / uint32(ipr.Workers)

	for min := sl; min <= el-step; min += step {
		max := min + step

		wg.Add(1)
		go func(min, max uint32) {
			for l := min; l <= max; l++ {
				b := make([]byte, 4)
				binary.BigEndian.PutUint32(b, l)
				fn(net.IP(b).To4())
			}

			wg.Done()
		}(min, max)
	}

	wg.Wait()
}

func CheckPort(ip string, port int, timeout time.Duration) bool {
	_, err := net.DialTimeout(`tcp`, ip+`:`+strconv.Itoa(port), timeout)
	if err != nil {
		return false
	}

	return true
}
