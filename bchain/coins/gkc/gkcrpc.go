package gkc

import (
	"encoding/json"
	"github.com/golang/glog"
	"github.com/trezor/blockbook/bchain"
	"github.com/trezor/blockbook/bchain/coins/btc"
)

// GKCRPC is an interface to JSON-RPC bitcoind service.
type GKCRPC struct {
	*btc.BitcoinRPC
}

// NewGKCRPC returns new GKCRPC instance.
func NewGKCRPC(config json.RawMessage, pushHandler func(bchain.NotificationType)) (bchain.BlockChain, error) {
	b, err := btc.NewBitcoinRPC(config, pushHandler)
	if err != nil {
		return nil, err
	}

	s := &GKCRPC{
		b.(*btc.BitcoinRPC),
	}
	s.RPCMarshaler = btc.JSONMarshalerV1{}
	s.ChainConfig.SupportsEstimateFee = true
	s.ChainConfig.SupportsEstimateSmartFee = false

	return s, nil
}

// Initialize initializes GKCRPC instance.
func (b *GKCRPC) Initialize() error {
	ci, err := b.GetChainInfo()
	if err != nil {
		return err
	}
	chainName := ci.Chain

	glog.Info("Chain name ", chainName)
	params := GetChainParams(chainName)

	// always create parser
	b.Parser = NewGKCParser(params, b.ChainConfig)

	// parameters for getInfo request
	if params.Net == MainnetMagic {
		b.Testnet = false
		b.Network = "livenet"
	} else {
		b.Testnet = true
		b.Network = "testnet"
	}

	glog.Info("rpc: block chain ", params.Name)

	return nil
}

// GetChainInfo returns information about the connected backend
func (b *GKCRPC) GetChainInfo() (*bchain.ChainInfo, error) {
	glog.V(1).Info("rpc: getblockchaininfo")

	resCi := btc.ResGetBlockChainInfo{}
	err := b.Call(&btc.CmdGetBlockChainInfo{Method: "getblockchaininfo"}, &resCi)
	if err != nil {
		return nil, err
	}
	if resCi.Error != nil {
		return nil, resCi.Error
	}

	//glog.V(1).Info("rpc: getnetworkinfo")
	resNi := btc.ResGetNetworkInfo{}
	//err = b.Call(&btc.CmdGetNetworkInfo{Method: "getnetworkinfo"}, &resNi)
	//if err != nil {
	//	return nil, err
	//}
	//if resNi.Error != nil {
	//	return nil, resNi.Error
	//}

	rv := &bchain.ChainInfo{
		Bestblockhash: resCi.Result.Bestblockhash,
		Blocks:        resCi.Result.Blocks,
		Chain:         resCi.Result.Chain,
		Difficulty:    string(resCi.Result.Difficulty),
		Headers:       resCi.Result.Headers,
		SizeOnDisk:    resCi.Result.SizeOnDisk,
		Subversion:    string(resNi.Result.Subversion),
		Timeoffset:    resNi.Result.Timeoffset,
	}
	rv.Version = string(resNi.Result.Version)
	rv.ProtocolVersion = string(resNi.Result.ProtocolVersion)
	if len(resCi.Result.Warnings) > 0 {
		rv.Warnings = resCi.Result.Warnings + " "
	}
	if resCi.Result.Warnings != resNi.Result.Warnings {
		rv.Warnings += resNi.Result.Warnings
	}
	return rv, nil
}