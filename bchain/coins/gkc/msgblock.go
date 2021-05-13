// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package gkc

import (
	"github.com/martinboehm/btcd/wire"
)


// MsgBlock implements the Message interface and represents a bitcoin
// block message.  It is used to deliver block and transaction information in
// response to a getdata message (MsgGetData) for a given block hash.
type MsgBlock struct {
	Header       wire.BlockHeader
	Transactions []*MsgTx
}

const (
	BlockVersion_Geness        = 1
	BlockVersion_Pow 	       = 2
	BlockVersion_Pos 	       = 3
	BlockVersion_Zerocoin 	   = 4
	BlockVersion_SmartContract = 5
)