package gkc

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/golang/glog"
	"github.com/juju/errors"
	"github.com/martinboehm/btcd/blockchain"
	"github.com/martinboehm/btcd/wire"
	"github.com/martinboehm/btcutil/chaincfg"
	"github.com/trezor/blockbook/bchain"
	"github.com/trezor/blockbook/bchain/coins/btc"
	"github.com/trezor/blockbook/bchain/coins/utils"
	"io"
	"math/big"
)

// magic numbers
const (
	MainnetMagic wire.BitcoinNet = 0xe9fdc491

	// Zerocoin op codes
	OP_ZEROCOINMINT  = 0xc1
	OP_ZEROCOINSPEND = 0xc2
)

// chain parameters
var (
	MainNetParams chaincfg.Params
)

func init() {
	// GKC mainnet Address encoding magics
	MainNetParams = chaincfg.MainNetParams
	MainNetParams.Net = MainnetMagic
	MainNetParams.PubKeyHashAddrID = []byte{38} // starting with 'G'
	MainNetParams.ScriptHashAddrID = []byte{5}
	MainNetParams.PrivateKeyID = []byte{128}
}

// GKCParser handle
type GKCParser struct {
	*btc.BitcoinParser
	baseparser                         *bchain.BaseParser
	BitcoinOutputScriptToAddressesFunc btc.OutputScriptToAddressesFunc
}

// NewGKCParser returns new GKCParser instance
func NewGKCParser(params *chaincfg.Params, c *btc.Configuration) *GKCParser {
	p := &GKCParser{
		BitcoinParser: btc.NewBitcoinParser(params, c),
		baseparser:    &bchain.BaseParser{},
	}
	p.BitcoinOutputScriptToAddressesFunc = p.OutputScriptToAddressesFunc
	p.OutputScriptToAddressesFunc = p.outputScriptToAddresses
	return p
}

// GetChainParams contains network parameters for the main PivX network
func GetChainParams(chain string) *chaincfg.Params {
	if !chaincfg.IsRegistered(&MainNetParams) {
		err := chaincfg.Register(&MainNetParams)
		if err != nil {
			panic(err)
		}
	}
	if chain != "main" {
		panic(fmt.Errorf("invalid chain %s", chain))
	}
	return &MainNetParams
}

// ParseBlock parses raw block to our Block struct
func (p *GKCParser) ParseBlock(b []byte) (*bchain.Block, error) {
	r := bytes.NewReader(b)
	w := MsgBlock{}
	h := wire.BlockHeader{}
	err := h.Deserialize(r)
	if err != nil {
		return nil, errors.Annotatef(err, "Deserialize")
	}

	if h.Version >= BlockVersion_Zerocoin {
		// Skip past AccumulatorCheckpoint (block version 4, 5 and after)
		r.Seek(32, io.SeekCurrent)
	}

	err = DecodeTransactions(r, 0, wire.WitnessEncoding, &w)
	if err != nil {
		glog.Infof("block %x", b)
		return nil, errors.Annotatef(err, "DecodeTransactions")
	}

	txs := make([]bchain.Tx, len(w.Transactions))
	for ti, t := range w.Transactions {
		txs[ti] = p.TxFromMsgTx(t, false)
	}

	return &bchain.Block{
		BlockHeader: bchain.BlockHeader{
			Size: len(b),
			Time: h.Timestamp.Unix(),
		},
		Txs: txs,
	}, nil
}

// PackTx packs transaction to byte array using protobuf
func (p *GKCParser) PackTx(tx *bchain.Tx, height uint32, blockTime int64) ([]byte, error) {
	return p.baseparser.PackTx(tx, height, blockTime)
}

// UnpackTx unpacks transaction from protobuf byte array
func (p *GKCParser) UnpackTx(buf []byte) (*bchain.Tx, uint32, error) {
	return p.baseparser.UnpackTx(buf)
}

// ParseTx parses byte array containing transaction and returns Tx struct
func (p *GKCParser) ParseTx(b []byte) (*bchain.Tx, error) {
	t := MsgTx{}
	r := bytes.NewReader(b)
	if err := t.Deserialize(r); err != nil {
		return nil, err
	}
	tx := p.TxFromMsgTx(&t, true)
	tx.Hex = hex.EncodeToString(b)
	return &tx, nil
}

// TxFromMsgTx parses tx and adds handling for OP_ZEROCOINSPEND inputs
func (p *GKCParser) TxFromMsgTx(t *MsgTx, parseAddresses bool) bchain.Tx {
	vin := make([]bchain.Vin, len(t.TxIn))
	for i, in := range t.TxIn {

		// extra check to not confuse Tx with single OP_ZEROCOINSPEND input as a coinbase Tx
		if !isZeroCoinSpendScript(in.SignatureScript) && blockchain.IsCoinBaseTx(&wire.MsgTx{Version: t.Version, TxIn: t.TxIn}) {
			vin[i] = bchain.Vin{
				Coinbase: hex.EncodeToString(in.SignatureScript),
				Sequence: in.Sequence,
			}
			break
		}

		s := bchain.ScriptSig{
			Hex: hex.EncodeToString(in.SignatureScript),
			// missing: Asm,
		}

		txid := in.PreviousOutPoint.Hash.String()

		vin[i] = bchain.Vin{
			Txid:      txid,
			Vout:      in.PreviousOutPoint.Index,
			Sequence:  in.Sequence,
			ScriptSig: s,
		}
	}
	vout := make([]bchain.Vout, len(t.TxOut))
	for i, out := range t.TxOut {
		addrs := []string{}
		if parseAddresses {
			addrs, _, _ = p.OutputScriptToAddressesFunc(out.PkScript)
		}
		s := bchain.ScriptPubKey{
			Hex:       hex.EncodeToString(out.PkScript),
			Addresses: addrs,
			// missing: Asm,
			// missing: Type,
		}
		var vs big.Int
		vs.SetInt64(out.Value)
		vout[i] = bchain.Vout{
			ValueSat:     vs,
			N:            uint32(i),
			ScriptPubKey: s,
		}
	}
	tx := bchain.Tx{
		Txid:     t.TxHash().String(),
		Version:  t.Version,
		LockTime: t.LockTime,
		Vin:      vin,
		Vout:     vout,
		// skip: BlockHash,
		// skip: Confirmations,
		// skip: Time,
		// skip: Blocktime,
	}
	return tx
}

// ParseTxFromJson parses JSON message containing transaction and returns Tx struct
func (p *GKCParser) ParseTxFromJson(msg json.RawMessage) (*bchain.Tx, error) {
	var tx bchain.Tx
	err := json.Unmarshal(msg, &tx)
	if err != nil {
		return nil, err
	}

	for i := range tx.Vout {
		vout := &tx.Vout[i]
		// convert vout.JsonValue to big.Int and clear it, it is only temporary value used for unmarshal
		vout.ValueSat, err = p.AmountToBigInt(vout.JsonValue)
		if err != nil {
			return nil, err
		}
		vout.JsonValue = ""

		if vout.ScriptPubKey.Addresses == nil {
			vout.ScriptPubKey.Addresses = []string{}
		}
	}

	return &tx, nil
}

// outputScriptToAddresses converts ScriptPubKey to bitcoin addresses
func (p *GKCParser) outputScriptToAddresses(script []byte) ([]string, bool, error) {
	if isZeroCoinSpendScript(script) {
		return []string{"Zerocoin Spend"}, false, nil
	}
	if isZeroCoinMintScript(script) {
		return []string{"Zerocoin Mint"}, false, nil
	}

	rv, s, _ := p.BitcoinOutputScriptToAddressesFunc(script)
	return rv, s, nil
}

func (p *GKCParser) GetAddrDescForUnknownInput(tx *bchain.Tx, input int) bchain.AddressDescriptor {
	if len(tx.Vin) > input {
		scriptHex := tx.Vin[input].ScriptSig.Hex

		if scriptHex != "" {
			script, _ := hex.DecodeString(scriptHex)
			return script
		}
	}

	s := make([]byte, 10)
	return s
}

// Checks if script is OP_ZEROCOINMINT
func isZeroCoinMintScript(signatureScript []byte) bool {
	return len(signatureScript) > 1 && signatureScript[0] == OP_ZEROCOINMINT
}

// Checks if script is OP_ZEROCOINSPEND
func isZeroCoinSpendScript(signatureScript []byte) bool {
	return len(signatureScript) >= 100 && signatureScript[0] == OP_ZEROCOINSPEND
}

// this is a fix of utils.DecodeTransactions, just for gkc
func DecodeTransactions(r io.Reader, pver uint32, enc wire.MessageEncoding, blk *MsgBlock) error {
	txCount, err := wire.ReadVarInt(r, pver)
	if err != nil {
		return err
	}

	// Prevent more transactions than could possibly fit into a block.
	// It would be possible to cause memory exhaustion and panics without
	// a sane upper bound on this count.
	if txCount > utils.MaxTxPerBlock {
		str := fmt.Sprintf("too many transactions to fit into a block "+
			"[count %d, max %d]", txCount, utils.MaxTxPerBlock)
		return &wire.MessageError{Func: "utils.decodeTransactions", Description: str}
	}

	blk.Transactions = make([]*MsgTx, 0, txCount)
	for i := uint64(0); i < txCount; i++ {
		tx := MsgTx{}
		err := tx.BtcDecode(r, pver, enc)
		if err != nil {
			return err
		}

		blk.Transactions = append(blk.Transactions, &tx)
	}

	return nil
}

func readUint32(r io.Reader) (uint32, error) {
	buf := make([]byte, 4, 4)
	n, err := r.Read(buf)
	if err != nil || n != 4 {
		return 0, fmt.Errorf("can't read uin32")
	}

	return binary.LittleEndian.Uint32(buf), nil
}

func readUint64(r io.Reader) (uint64, error) {
	buf := make([]byte, 8, 8)
	n, err := r.Read(buf)
	if err != nil || n != 8 {
		return 0, fmt.Errorf("can't read uin64")
	}

	return binary.LittleEndian.Uint64(buf), nil
}
