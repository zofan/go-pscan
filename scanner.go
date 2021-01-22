package ipscan

import (
	"encoding/binary"
	"encoding/json"
	"io/ioutil"
	"math"
	"net"
	"os"
	"sync"
)

type Scanner struct {
	MinIP   string
	MaxIP   string
	Threads uint64

	Metric struct {
		Count uint64
		Done  uint64
	}

	Workers []*Worker

	mu sync.Mutex
	wg *sync.WaitGroup
}

func NewScanner(minIP, maxIP string, threads uint64) *Scanner {
	s := &Scanner{
		MinIP:   minIP,
		MaxIP:   maxIP,
		Threads: threads,

		wg: &sync.WaitGroup{},
	}

	s.addWorkers()

	return s
}

func (s *Scanner) addWorkers() {
	sl := uint64(binary.BigEndian.Uint32(net.ParseIP(s.MinIP).To4()))
	el := uint64(binary.BigEndian.Uint32(net.ParseIP(s.MaxIP).To4()))

	var step = math.Ceil(float64(el-sl) / float64(s.Threads))
	stepInt := uint64(step)
	s.Metric.Count = el - sl

	for min := sl; min < el; min += stepInt {
		max := min + stepInt
		if max > el {
			max = el
		}

		s.addWorker(min, max)
	}
}

func (s *Scanner) addWorker(min, max uint64) {
	w := &Worker{
		MinLong: min,
		MaxLong: max,
		CurLong: min,
		OkLong:  min,
	}

	s.Workers = append(s.Workers, w)
}

func (s *Scanner) Each(fn func(ip net.IP) bool) {
	for _, w := range s.Workers {
		s.wg.Add(1)

		go func(s *Scanner, w *Worker) {
			w.Each(fn)

			s.wg.Done()
		}(s, w)
	}

	s.wg.Wait()
}

func (s *Scanner) SendSignal(signal WorkerSignal) {
	s.mu.Lock()

	for _, w := range s.Workers {
		w.Signal = signal
	}

	s.mu.Unlock()
}

func (s *Scanner) SaveFile(file string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	raw, err := json.Marshal(s)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(file, raw, 0664)
}

func (s *Scanner) LoadFile(file string) error {
	raw, err := ioutil.ReadFile(file)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}

		return err
	}

	return json.Unmarshal(raw, &s)
}
