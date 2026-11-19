//go:build !windows

package main

import (
	"os"
	"os/signal"
	"syscall"
)

// notifyHangup wires SIGHUP into the model reload path on Unix.
func notifyHangup(ch chan<- os.Signal) {
	signal.Notify(ch, syscall.SIGHUP)
}
