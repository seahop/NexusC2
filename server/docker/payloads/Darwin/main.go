//go:build darwin && !build_dylib
// +build darwin,!build_dylib

package main

func main() {
	startPayload()
	select {}
}
