//go:build darwin && build_dylib
// +build darwin,build_dylib

package main

import "C"

func init() {
	go startPayload()
}

func main() {}
