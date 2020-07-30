/*
  This file includes tests for key management.
*/
package km

import (
	"os"
	"testing"
)

func TestSavePrvKey(t *testing.T) {
	path := "./test.key"
	password := "123456"
	prvkey := "ea07ded1156e152ef8615661581cf73495c33b431f3fbe372f57370dc80b375b"
	err := SavePrvKey(path, password, prvkey)
	if err != nil {
		t.Fatalf("failed to save private key: %v", err)
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatalf("failed to save private key")
	}
}

func TestReadPrvKey(t *testing.T) {
	path := "./test.key"
	password := "123456"
	prvkey, err := ReadPrvKey(path, password)
	if err != nil {
		t.Fatalf("failed to load private key: %v", err)
	}
    if prvkey != "ea07ded1156e152ef8615661581cf73495c33b431f3fbe372f57370dc80b375b" {
    	t.Fatalf("loaded wrong private key")
	}
}

func TestSaveBds(t *testing.T) {
	bds := "91116513514782453972094334385061412725609779292736304247441591947503997353352"
	path := "./bds_test"
	password := "123456"
	err := SaveBds(bds, path, password)
	if err != nil {
		t.Fatalf("failed to save bds: %v", err)
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatalf("failed to save bds")
	}
}

// load bds from file and decrypt bds using password
func TestLoadBdsFromFile(t *testing.T) {
	path := "./bds_test"
	password := "123456"
	bds, err := LoadBdsFromFile(path, password)
	if err != nil {
		t.Fatalf("failed to load bds: %v", err)
	}
	if bds != "91116513514782453972094334385061412725609779292736304247441591947503997353352" {
		t.Fatalf("loaded wrong bds")
	}
}
