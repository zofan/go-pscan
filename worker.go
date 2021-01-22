package ipscan

import (
	"encoding/binary"
	"net"
	"time"
)

const (
	SignalRestart WorkerSignal = `Restart`
	SignalStop    WorkerSignal = `Stop`
	SignalPause   WorkerSignal = `Pause`
	SignalResume  WorkerSignal = `Resume`
)

type WorkerSignal string

type Worker struct {
	MinLong uint64
	MaxLong uint64
	CurLong uint64
	OkLong  uint64

	Signal WorkerSignal
}

func (w *Worker) Each(fn func(ip net.IP) bool) {
	w.Signal = ``

	for l := w.CurLong; l <= w.MaxLong; l++ {
		switch w.Signal {
		case SignalStop:
			break
		case SignalRestart:
			l = w.MinLong
			w.Signal = ``
		case SignalPause:
			for w.Signal != SignalPause {
				time.Sleep(time.Millisecond * 100)
				w.Signal = ``
			}
		}

		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, uint32(l))

		w.CurLong = l

		if fn(net.IP(b).To4()) {
			w.OkLong = l
		}
	}
}

func (w *Worker) SendSignal(signal WorkerSignal) {
	w.Signal = signal
}
