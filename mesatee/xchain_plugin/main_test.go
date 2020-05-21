package main

import (
	"testing"
)

func TestInit(t *testing.T) {
	err := Init("./teeconfig.conf")
	if err != nil {
		t.Fatal(err)
	}
}
