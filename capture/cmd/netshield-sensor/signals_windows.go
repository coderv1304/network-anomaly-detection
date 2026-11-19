//go:build windows

package main

import "os"

// notifyHangup is a no-op on Windows; the 5s SHA watch still reloads models.
func notifyHangup(chan<- os.Signal) {}
