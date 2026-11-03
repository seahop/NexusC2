//go:build linux

package main

var featureHandlers []featureReg

type featureReg struct {
	id      int
	handler OpHandler
}

func registerFeature(id int, handler OpHandler) {
	featureHandlers = append(featureHandlers, featureReg{id: id, handler: handler})
}
