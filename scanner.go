package pscan

import (
	"encoding/binary"
	"encoding/json"
	"io/ioutil"
	"net"
	"os"
	"sync"
)

type Scanner struct {
	MinIP    string
	MaxIP    string
	Parallel int

	Metric struct {
		Count uint64
		Done  uint64
	}

	workers []*Worker

	mu sync.Mutex
	wg *sync.WaitGroup
}

func (s *Scanner) Spawn(min, max uint64) {
	w := &Worker{
		MinLong: min,
		MaxLong: max,
		CurLong: min,
		OkLong:  min,
	}

	s.workers = append(s.workers, w)
	s.wg.Add(1)
}

func (s *Scanner) Each(fn func(ip net.IP) bool) {
	s.wg = &sync.WaitGroup{}

	sl := uint64(binary.BigEndian.Uint32(net.ParseIP(s.MinIP).To4()))
	el := uint64(binary.BigEndian.Uint32(net.ParseIP(s.MaxIP).To4()))

	step := (el - sl) / uint64(s.Parallel)
	s.Metric.Count = el - sl

	var wn int
	for min := sl - 1; min < el; min += step {
		max := min + step
		if max > el {
			max = el
		}

		go func(s *Scanner, w *Worker) {
			w.Each(fn)

			s.wg.Done()
		}(s, s.workers[wn])

		wn++
	}

	s.wg.Wait()
}

func (s *Scanner) SendSignal(signal WorkerSignal) {
	s.mu.Lock()

	for _, s := range s.workers {
		s.Signal = signal
	}

	s.mu.Unlock()
}

func (s *Scanner) SaveWorkers(file string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	raw, err := json.Marshal(s.workers)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(file, raw, 0664)
}

func (s *Scanner) LoadWorkers(file string) error {
	raw, err := ioutil.ReadFile(file)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}

		return err
	}

	return json.Unmarshal(raw, &s.workers)
}
