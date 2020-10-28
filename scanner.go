package pscan

import (
	"encoding/binary"
	"encoding/json"
	"io/ioutil"
	"math"
	"net"
	"os"
	"strconv"
	"sync"
	"time"
)

type IpRange struct {
	Start   string
	End     string
	Workers int

	State map[int]uint64
	Count uint64
	Done  uint64

	mu sync.Mutex
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

func (ipr *IpRange) Each(fn func(ip net.IP) bool) {
	wg := &sync.WaitGroup{}

	sl := uint64(binary.BigEndian.Uint32(net.ParseIP(ipr.Start).To4()))
	el := uint64(binary.BigEndian.Uint32(net.ParseIP(ipr.End).To4()))

	step := (el - sl) / uint64(ipr.Workers)

	ipr.Count = el - sl

	if len(ipr.State) == 0 {
		ipr.State = make(map[int]uint64)
	}

	var w int
	for min := sl - 1; min < el; min += step {
		max := min + step
		if max > el {
			max = el
		}

		wg.Add(1)
		go func(min, max uint64, w int) {
			ipr.mu.Lock()
			if state, ok := ipr.State[w]; ok {
				ipr.Done += state - min
				min = state
			}
			ipr.mu.Unlock()

			for l := min; l <= max; l++ {
				b := make([]byte, 4)
				binary.BigEndian.PutUint32(b, uint32(l))

				if fn(net.IP(b).To4()) {
					ipr.mu.Lock()
					ipr.State[w] = l
					ipr.mu.Unlock()
				}

				ipr.mu.Lock()
				ipr.Done++
				ipr.mu.Unlock()
			}

			wg.Done()
		}(min, max, w)

		w++
	}

	wg.Wait()
}

func (ipr *IpRange) SaveState(file string) error {
	ipr.mu.Lock()
	defer ipr.mu.Unlock()

	raw, err := json.Marshal(ipr.State)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(file, raw, 0664)
}

func (ipr *IpRange) LoadState(file string) error {
	raw, err := ioutil.ReadFile(file)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}

		return err
	}

	return json.Unmarshal(raw, &ipr.State)
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

func CheckPort(ip string, port int, timeout time.Duration) bool {
	_, err := net.DialTimeout(`tcp`, ip+`:`+strconv.Itoa(port), timeout)
	if err != nil {
		return false
	}

	return true
}

func ExternalIP(ip net.IP) bool {
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
