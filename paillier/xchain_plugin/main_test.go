package main

import (
	"testing"
)

func TestInit(t *testing.T) {
	err := Init("./paillierconfig.conf")
	if err != nil {
		t.Fatal(err)
	}
}
