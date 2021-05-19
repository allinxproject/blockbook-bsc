package fch

import (
	"github.com/martinboehm/btcutil"
	"testing"
)

func TestDecodeAddr(t *testing.T) {
	address := "FNPS1kAH6XiY4eST2fnA8E1kAwo1VB9vYc"

	params := GetChainParams("main")

	da, err := btcutil.DecodeAddress(address, params)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("%+v", da)
}
