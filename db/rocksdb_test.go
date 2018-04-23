package db

import (
	"blockbook/bchain"
	"blockbook/bchain/coins/btc"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/juju/errors"
)

func setupRocksDB(t *testing.T, p bchain.BlockChainParser) *RocksDB {
	tmp, err := ioutil.TempDir("", "testdb")
	if err != nil {
		t.Fatal(err)
	}
	d, err := NewRocksDB(tmp, p)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func closeAnddestroyRocksDB(t *testing.T, d *RocksDB) {
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	os.RemoveAll(d.path)
}

func addressToPubKeyHex(addr string, t *testing.T, d *RocksDB) string {
	b, err := d.chainParser.AddressToOutputScript(addr)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func addressToPubKeyHexWithLength(addr string, t *testing.T, d *RocksDB) string {
	h := addressToPubKeyHex(addr, t, d)
	// length is signed varint, therefore 2 times big, we can take len(h) as the correct value
	return strconv.FormatInt(int64(len(h)), 16) + h
}

// keyPair is used to compare given key value in DB with expected
// for more complicated compares it is possible to specify CompareFunc
type keyPair struct {
	Key, Value  string
	CompareFunc func(string) bool
}

func compareFuncBlockAddresses(v string, expected []string) bool {
	for _, e := range expected {
		lb := len(v)
		v = strings.Replace(v, e, "", 1)
		if lb == len(v) {
			return false
		}
	}
	return len(v) == 0
}

func checkColumn(d *RocksDB, col int, kp []keyPair) error {
	sort.Slice(kp, func(i, j int) bool {
		return kp[i].Key < kp[j].Key
	})
	it := d.db.NewIteratorCF(d.ro, d.cfh[col])
	defer it.Close()
	i := 0
	for it.SeekToFirst(); it.Valid(); it.Next() {
		if i >= len(kp) {
			return errors.Errorf("Expected less rows in column %v", col)
		}
		key := hex.EncodeToString(it.Key().Data())
		if key != kp[i].Key {
			return errors.Errorf("Incorrect key %v found in column %v row %v, expecting %v", key, col, i, kp[i].Key)
		}
		val := hex.EncodeToString(it.Value().Data())
		var valOK bool
		if kp[i].CompareFunc == nil {
			valOK = val == kp[i].Value
		} else {
			valOK = kp[i].CompareFunc(val)
		}
		if !valOK {
			return errors.Errorf("Incorrect value %v found in column %v row %v, expecting %v", val, col, i, kp[i].Value)
		}
		i++
	}
	if i != len(kp) {
		return errors.Errorf("Expected more rows in column %v: got %v, expected %v", col, i, len(kp))
	}
	return nil
}

func getTestUTXOBlock1(t *testing.T, d *RocksDB) *bchain.Block {
	return &bchain.Block{
		BlockHeader: bchain.BlockHeader{
			Height: 225493,
			Hash:   "0000000076fbbed90fd75b0e18856aa35baa984e9c9d444cf746ad85e94e2997",
		},
		Txs: []bchain.Tx{
			bchain.Tx{
				Txid: "00b2c06055e5e90e9c82bd4181fde310104391a7fa4f289b1704e5d90caa3840",
				Vout: []bchain.Vout{
					bchain.Vout{
						N: 0,
						ScriptPubKey: bchain.ScriptPubKey{
							Hex: addressToPubKeyHex("mfcWp7DB6NuaZsExybTTXpVgWz559Np4Ti", t, d),
						},
					},
					bchain.Vout{
						N: 1,
						ScriptPubKey: bchain.ScriptPubKey{
							Hex: addressToPubKeyHex("mtGXQvBowMkBpnhLckhxhbwYK44Gs9eEtz", t, d),
						},
					},
				},
				Blocktime: 22549300000,
				Time:      22549300000,
			},
			bchain.Tx{
				Txid: "effd9ef509383d536b1c8af5bf434c8efbf521a4f2befd4022bbd68694b4ac75",
				Vout: []bchain.Vout{
					bchain.Vout{
						N: 0,
						ScriptPubKey: bchain.ScriptPubKey{
							Hex: addressToPubKeyHex("mv9uLThosiEnGRbVPS7Vhyw6VssbVRsiAw", t, d),
						},
					},
					bchain.Vout{
						N: 1,
						ScriptPubKey: bchain.ScriptPubKey{
							Hex: addressToPubKeyHex("2Mz1CYoppGGsLNUGF2YDhTif6J661JitALS", t, d),
						},
					},
				},
				Blocktime: 22549300001,
				Time:      22549300001,
			},
		},
	}
}

func getTestUTXOBlock2(t *testing.T, d *RocksDB) *bchain.Block {
	return &bchain.Block{
		BlockHeader: bchain.BlockHeader{
			Height: 225494,
			Hash:   "00000000eb0443fd7dc4a1ed5c686a8e995057805f9a161d9a5a77a95e72b7b6",
		},
		Txs: []bchain.Tx{
			bchain.Tx{
				Txid: "7c3be24063f268aaa1ed81b64776798f56088757641a34fb156c4f51ed2e9d25",
				Vin: []bchain.Vin{
					bchain.Vin{
						Txid: "effd9ef509383d536b1c8af5bf434c8efbf521a4f2befd4022bbd68694b4ac75",
						Vout: 0,
					},
					bchain.Vin{
						Txid: "00b2c06055e5e90e9c82bd4181fde310104391a7fa4f289b1704e5d90caa3840",
						Vout: 1,
					},
				},
				Vout: []bchain.Vout{
					bchain.Vout{
						N: 0,
						ScriptPubKey: bchain.ScriptPubKey{
							Hex: addressToPubKeyHex("mzB8cYrfRwFRFAGTDzV8LkUQy5BQicxGhX", t, d),
						},
					},
					bchain.Vout{
						N: 1,
						ScriptPubKey: bchain.ScriptPubKey{
							Hex: addressToPubKeyHex("mtR97eM2HPWVM6c8FGLGcukgaHHQv7THoL", t, d),
						},
					},
				},
				Blocktime: 22549400000,
				Time:      22549400000,
			},
			bchain.Tx{
				Txid: "3d90d15ed026dc45e19ffb52875ed18fa9e8012ad123d7f7212176e2b0ebdb71",
				Vin: []bchain.Vin{
					bchain.Vin{
						Txid: "7c3be24063f268aaa1ed81b64776798f56088757641a34fb156c4f51ed2e9d25",
						Vout: 0,
					},
					bchain.Vin{
						Txid: "effd9ef509383d536b1c8af5bf434c8efbf521a4f2befd4022bbd68694b4ac75",
						Vout: 1,
					},
				},
				Vout: []bchain.Vout{
					bchain.Vout{
						N: 0,
						ScriptPubKey: bchain.ScriptPubKey{
							Hex: addressToPubKeyHex("mwwoKQE5Lb1G4picHSHDQKg8jw424PF9SC", t, d),
						},
					},
					bchain.Vout{
						N: 1,
						ScriptPubKey: bchain.ScriptPubKey{
							Hex: addressToPubKeyHex("mmJx9Y8ayz9h14yd9fgCW1bUKoEpkBAquP", t, d),
						},
					},
				},
				Blocktime: 22549400001,
				Time:      22549400001,
			},
		},
	}
}

func verifyAfterUTXOBlock1(t *testing.T, d *RocksDB, noBlockAddresses bool) {
	if err := checkColumn(d, cfHeight, []keyPair{
		keyPair{"000370d5", "0000000076fbbed90fd75b0e18856aa35baa984e9c9d444cf746ad85e94e2997", nil},
	}); err != nil {
		{
			t.Fatal(err)
		}
	}
	// the vout is encoded as signed varint, i.e. value * 2 for non negative values
	if err := checkColumn(d, cfAddresses, []keyPair{
		keyPair{addressToPubKeyHex("mfcWp7DB6NuaZsExybTTXpVgWz559Np4Ti", t, d) + "000370d5", "00b2c06055e5e90e9c82bd4181fde310104391a7fa4f289b1704e5d90caa3840" + "00", nil},
		keyPair{addressToPubKeyHex("mtGXQvBowMkBpnhLckhxhbwYK44Gs9eEtz", t, d) + "000370d5", "00b2c06055e5e90e9c82bd4181fde310104391a7fa4f289b1704e5d90caa3840" + "02", nil},
		keyPair{addressToPubKeyHex("mv9uLThosiEnGRbVPS7Vhyw6VssbVRsiAw", t, d) + "000370d5", "effd9ef509383d536b1c8af5bf434c8efbf521a4f2befd4022bbd68694b4ac75" + "00", nil},
		keyPair{addressToPubKeyHex("2Mz1CYoppGGsLNUGF2YDhTif6J661JitALS", t, d) + "000370d5", "effd9ef509383d536b1c8af5bf434c8efbf521a4f2befd4022bbd68694b4ac75" + "02", nil},
	}); err != nil {
		{
			t.Fatal(err)
		}
	}
	if err := checkColumn(d, cfUnspentTxs, []keyPair{
		keyPair{
			"00b2c06055e5e90e9c82bd4181fde310104391a7fa4f289b1704e5d90caa3840",
			addressToPubKeyHexWithLength("mfcWp7DB6NuaZsExybTTXpVgWz559Np4Ti", t, d) + "00" + addressToPubKeyHexWithLength("mtGXQvBowMkBpnhLckhxhbwYK44Gs9eEtz", t, d) + "02",
			nil,
		},
		keyPair{
			"effd9ef509383d536b1c8af5bf434c8efbf521a4f2befd4022bbd68694b4ac75",
			addressToPubKeyHexWithLength("mv9uLThosiEnGRbVPS7Vhyw6VssbVRsiAw", t, d) + "00" + addressToPubKeyHexWithLength("2Mz1CYoppGGsLNUGF2YDhTif6J661JitALS", t, d) + "02",
			nil,
		},
	}); err != nil {
		{
			t.Fatal(err)
		}
	}
	// after disconnect there are no blockaddresses for the previous block
	var blockAddressesKp []keyPair
	if noBlockAddresses {
		blockAddressesKp = []keyPair{}
	} else {
		// the values in cfBlockAddresses have random order, must use CompareFunc
		blockAddressesKp = []keyPair{
			keyPair{"000370d5", "",
				func(v string) bool {
					return compareFuncBlockAddresses(v, []string{
						addressToPubKeyHexWithLength("mfcWp7DB6NuaZsExybTTXpVgWz559Np4Ti", t, d),
						addressToPubKeyHexWithLength("mtGXQvBowMkBpnhLckhxhbwYK44Gs9eEtz", t, d),
						addressToPubKeyHexWithLength("mv9uLThosiEnGRbVPS7Vhyw6VssbVRsiAw", t, d),
						addressToPubKeyHexWithLength("2Mz1CYoppGGsLNUGF2YDhTif6J661JitALS", t, d),
					})
				},
			},
		}
	}
	if err := checkColumn(d, cfBlockAddresses, blockAddressesKp); err != nil {
		{
			t.Fatal(err)
		}
	}
}

func verifyAfterUTXOBlock2(t *testing.T, d *RocksDB) {
	if err := checkColumn(d, cfHeight, []keyPair{
		keyPair{"000370d5", "0000000076fbbed90fd75b0e18856aa35baa984e9c9d444cf746ad85e94e2997", nil},
		keyPair{"000370d6", "00000000eb0443fd7dc4a1ed5c686a8e995057805f9a161d9a5a77a95e72b7b6", nil},
	}); err != nil {
		{
			t.Fatal(err)
		}
	}
	if err := checkColumn(d, cfAddresses, []keyPair{
		keyPair{addressToPubKeyHex("mfcWp7DB6NuaZsExybTTXpVgWz559Np4Ti", t, d) + "000370d5", "00b2c06055e5e90e9c82bd4181fde310104391a7fa4f289b1704e5d90caa3840" + "00", nil},
		keyPair{addressToPubKeyHex("mtGXQvBowMkBpnhLckhxhbwYK44Gs9eEtz", t, d) + "000370d5", "00b2c06055e5e90e9c82bd4181fde310104391a7fa4f289b1704e5d90caa3840" + "02", nil},
		keyPair{addressToPubKeyHex("mv9uLThosiEnGRbVPS7Vhyw6VssbVRsiAw", t, d) + "000370d5", "effd9ef509383d536b1c8af5bf434c8efbf521a4f2befd4022bbd68694b4ac75" + "00", nil},
		keyPair{addressToPubKeyHex("2Mz1CYoppGGsLNUGF2YDhTif6J661JitALS", t, d) + "000370d5", "effd9ef509383d536b1c8af5bf434c8efbf521a4f2befd4022bbd68694b4ac75" + "02", nil},
		keyPair{addressToPubKeyHex("mzB8cYrfRwFRFAGTDzV8LkUQy5BQicxGhX", t, d) + "000370d6", "7c3be24063f268aaa1ed81b64776798f56088757641a34fb156c4f51ed2e9d25" + "00" + "3d90d15ed026dc45e19ffb52875ed18fa9e8012ad123d7f7212176e2b0ebdb71" + "01", nil},
		keyPair{addressToPubKeyHex("mtR97eM2HPWVM6c8FGLGcukgaHHQv7THoL", t, d) + "000370d6", "7c3be24063f268aaa1ed81b64776798f56088757641a34fb156c4f51ed2e9d25" + "02", nil},
		keyPair{addressToPubKeyHex("mwwoKQE5Lb1G4picHSHDQKg8jw424PF9SC", t, d) + "000370d6", "3d90d15ed026dc45e19ffb52875ed18fa9e8012ad123d7f7212176e2b0ebdb71" + "00", nil},
		keyPair{addressToPubKeyHex("mmJx9Y8ayz9h14yd9fgCW1bUKoEpkBAquP", t, d) + "000370d6", "3d90d15ed026dc45e19ffb52875ed18fa9e8012ad123d7f7212176e2b0ebdb71" + "02", nil},
		keyPair{addressToPubKeyHex("mv9uLThosiEnGRbVPS7Vhyw6VssbVRsiAw", t, d) + "000370d6", "7c3be24063f268aaa1ed81b64776798f56088757641a34fb156c4f51ed2e9d25" + "01", nil},
		keyPair{addressToPubKeyHex("mtGXQvBowMkBpnhLckhxhbwYK44Gs9eEtz", t, d) + "000370d6", "7c3be24063f268aaa1ed81b64776798f56088757641a34fb156c4f51ed2e9d25" + "03", nil},
		keyPair{addressToPubKeyHex("2Mz1CYoppGGsLNUGF2YDhTif6J661JitALS", t, d) + "000370d6", "3d90d15ed026dc45e19ffb52875ed18fa9e8012ad123d7f7212176e2b0ebdb71" + "03", nil},
	}); err != nil {
		{
			t.Fatal(err)
		}
	}
	if err := checkColumn(d, cfUnspentTxs, []keyPair{
		keyPair{
			"00b2c06055e5e90e9c82bd4181fde310104391a7fa4f289b1704e5d90caa3840",
			addressToPubKeyHexWithLength("mfcWp7DB6NuaZsExybTTXpVgWz559Np4Ti", t, d) + "00",
			nil,
		},
		keyPair{
			"7c3be24063f268aaa1ed81b64776798f56088757641a34fb156c4f51ed2e9d25",
			addressToPubKeyHexWithLength("mtR97eM2HPWVM6c8FGLGcukgaHHQv7THoL", t, d) + "02",
			nil,
		},
		keyPair{
			"3d90d15ed026dc45e19ffb52875ed18fa9e8012ad123d7f7212176e2b0ebdb71",
			addressToPubKeyHexWithLength("mwwoKQE5Lb1G4picHSHDQKg8jw424PF9SC", t, d) + "00" + addressToPubKeyHexWithLength("mmJx9Y8ayz9h14yd9fgCW1bUKoEpkBAquP", t, d) + "02",
			nil,
		},
	}); err != nil {
		{
			t.Fatal(err)
		}
	}
	if err := checkColumn(d, cfBlockAddresses, []keyPair{
		keyPair{"000370d6", "",
			func(v string) bool {
				return compareFuncBlockAddresses(v, []string{
					addressToPubKeyHexWithLength("mzB8cYrfRwFRFAGTDzV8LkUQy5BQicxGhX", t, d),
					addressToPubKeyHexWithLength("mtR97eM2HPWVM6c8FGLGcukgaHHQv7THoL", t, d),
					addressToPubKeyHexWithLength("mwwoKQE5Lb1G4picHSHDQKg8jw424PF9SC", t, d),
					addressToPubKeyHexWithLength("mmJx9Y8ayz9h14yd9fgCW1bUKoEpkBAquP", t, d),
					addressToPubKeyHexWithLength("mv9uLThosiEnGRbVPS7Vhyw6VssbVRsiAw", t, d),
					addressToPubKeyHexWithLength("mtGXQvBowMkBpnhLckhxhbwYK44Gs9eEtz", t, d),
					addressToPubKeyHexWithLength("2Mz1CYoppGGsLNUGF2YDhTif6J661JitALS", t, d),
				})
			},
		},
	}); err != nil {
		{
			t.Fatal(err)
		}
	}
}

type txidVoutOutput struct {
	txid     string
	vout     uint32
	isOutput bool
}

func verifyGetTransactions(t *testing.T, d *RocksDB, addr string, low, high uint32, wantTxids []txidVoutOutput, wantErr error) {
	gotTxids := make([]txidVoutOutput, 0)
	addToTxids := func(txid string, vout uint32, isOutput bool) error {
		gotTxids = append(gotTxids, txidVoutOutput{txid, vout, isOutput})
		return nil
	}
	if err := d.GetTransactions(addr, low, high, addToTxids); err != nil {
		if wantErr == nil || wantErr.Error() != err.Error() {
			t.Fatal(err)
		}
	}
	if !reflect.DeepEqual(gotTxids, wantTxids) {
		t.Errorf("GetTransactions() = %v, want %v", gotTxids, wantTxids)
	}
}

type testBitcoinParser struct {
	*btc.BitcoinParser
}

// override btc.KeepBlockAddresses to keep only one blockaddress
func (p *testBitcoinParser) KeepBlockAddresses() int {
	return 1
}

// override PackTx and UnpackTx to default BaseParser functionality
// BitcoinParser uses tx hex which is not available for the test transactions
func (p *testBitcoinParser) PackTx(tx *bchain.Tx, height uint32, blockTime int64) ([]byte, error) {
	return p.BaseParser.PackTx(tx, height, blockTime)
}

func (p *testBitcoinParser) UnpackTx(buf []byte) (*bchain.Tx, uint32, error) {
	return p.BaseParser.UnpackTx(buf)
}

func testTxCache(t *testing.T, d *RocksDB, b *bchain.Block, tx *bchain.Tx) {
	if err := d.PutTx(tx, b.Height, tx.Blocktime); err != nil {
		t.Fatal(err)
	}
	gtx, height, err := d.GetTx(tx.Txid)
	if err != nil {
		t.Fatal(err)
	}
	if b.Height != height {
		t.Fatalf("GetTx: got height %v, expected %v", height, b.Height)
	}
	if fmt.Sprint(gtx) != fmt.Sprint(tx) {
		t.Errorf("GetTx: %v, want %v", gtx, tx)
	}
	if err := d.DeleteTx(tx.Txid); err != nil {
		t.Fatal(err)
	}
}

// TestRocksDB_Index_UTXO is an integration test probing the whole indexing functionality for UTXO chains
// It does the following:
// 1) Connect two blocks (inputs from 2nd block are spending some outputs from the 1st block)
// 2) GetTransactions for various addresses / low-high ranges
// 3) GetBestBlock, GetBlockHash
// 4) Test tx caching functionality
// 5) Disconnect block 2 - expect error
// 6) Disconnect the block 2 using blockaddresses column
// 7) Reconnect block 2 and disconnect blocks 1 and 2 using full scan
// After each step, the content of DB is examined and any difference against expected state is regarded as failure
func TestRocksDB_Index_UTXO(t *testing.T) {
	d := setupRocksDB(t, &testBitcoinParser{BitcoinParser: &btc.BitcoinParser{Params: btc.GetChainParams("test")}})
	defer closeAnddestroyRocksDB(t, d)

	// connect 1st block - will log warnings about missing UTXO transactions in cfUnspentTxs column
	block1 := getTestUTXOBlock1(t, d)
	if err := d.ConnectBlock(block1); err != nil {
		t.Fatal(err)
	}
	verifyAfterUTXOBlock1(t, d, false)

	// connect 2nd block - use some outputs from the 1st block as the inputs and 1 input uses tx from the same block
	block2 := getTestUTXOBlock2(t, d)
	if err := d.ConnectBlock(block2); err != nil {
		t.Fatal(err)
	}
	verifyAfterUTXOBlock2(t, d)

	// get transactions for various addresses / low-high ranges
	verifyGetTransactions(t, d, "mtGXQvBowMkBpnhLckhxhbwYK44Gs9eEtz", 0, 1000000, []txidVoutOutput{
		txidVoutOutput{"00b2c06055e5e90e9c82bd4181fde310104391a7fa4f289b1704e5d90caa3840", 1, true},
		txidVoutOutput{"7c3be24063f268aaa1ed81b64776798f56088757641a34fb156c4f51ed2e9d25", 1, false},
	}, nil)
	verifyGetTransactions(t, d, "mtGXQvBowMkBpnhLckhxhbwYK44Gs9eEtz", 225493, 225493, []txidVoutOutput{
		txidVoutOutput{"00b2c06055e5e90e9c82bd4181fde310104391a7fa4f289b1704e5d90caa3840", 1, true},
	}, nil)
	verifyGetTransactions(t, d, "mtGXQvBowMkBpnhLckhxhbwYK44Gs9eEtz", 225494, 1000000, []txidVoutOutput{
		txidVoutOutput{"7c3be24063f268aaa1ed81b64776798f56088757641a34fb156c4f51ed2e9d25", 1, false},
	}, nil)
	verifyGetTransactions(t, d, "mtGXQvBowMkBpnhLckhxhbwYK44Gs9eEtz", 500000, 1000000, []txidVoutOutput{}, nil)
	verifyGetTransactions(t, d, "mwwoKQE5Lb1G4picHSHDQKg8jw424PF9SC", 0, 1000000, []txidVoutOutput{
		txidVoutOutput{"3d90d15ed026dc45e19ffb52875ed18fa9e8012ad123d7f7212176e2b0ebdb71", 0, true},
	}, nil)
	verifyGetTransactions(t, d, "mtGXQvBowMkBpnhLckhxhbwYK44Gs9eBad", 500000, 1000000, []txidVoutOutput{}, errors.New("checksum mismatch"))

	// GetBestBlock
	height, hash, err := d.GetBestBlock()
	if err != nil {
		t.Fatal(err)
	}
	if height != 225494 {
		t.Fatalf("GetBestBlock: got height %v, expected %v", height, 225494)
	}
	if hash != "00000000eb0443fd7dc4a1ed5c686a8e995057805f9a161d9a5a77a95e72b7b6" {
		t.Fatalf("GetBestBlock: got hash %v, expected %v", hash, "00000000eb0443fd7dc4a1ed5c686a8e995057805f9a161d9a5a77a95e72b7b6")
	}

	// GetBlockHash
	hash, err = d.GetBlockHash(225493)
	if err != nil {
		t.Fatal(err)
	}
	if hash != "0000000076fbbed90fd75b0e18856aa35baa984e9c9d444cf746ad85e94e2997" {
		t.Fatalf("GetBlockHash: got hash %v, expected %v", hash, "0000000076fbbed90fd75b0e18856aa35baa984e9c9d444cf746ad85e94e2997")
	}

	// Test tx caching functionality, leave one tx in db to test cleanup in DisconnectBlock
	testTxCache(t, d, block1, &block1.Txs[0])
	testTxCache(t, d, block2, &block2.Txs[0])
	if err = d.PutTx(&block2.Txs[1], block2.Height, block2.Txs[1].Blocktime); err != nil {
		t.Fatal(err)
	}
	// check that there is only the last tx in the cache
	packedTx, err := d.chainParser.PackTx(&block2.Txs[1], block2.Height, block2.Txs[1].Blocktime)
	if err := checkColumn(d, cfTransactions, []keyPair{
		keyPair{block2.Txs[1].Txid, hex.EncodeToString(packedTx), nil},
	}); err != nil {
		{
			t.Fatal(err)
		}
	}

	// DisconnectBlock for UTXO chains is not possible
	err = d.DisconnectBlock(block2)
	if err == nil || err.Error() != "DisconnectBlock is not supported for UTXO chains" {
		t.Fatal(err)
	}
	verifyAfterUTXOBlock2(t, d)

	// disconnect the 2nd block, verify that the db contains only data from the 1st block with restored unspentTxs
	// and that the cached tx is removed
	err = d.DisconnectBlockRange(225494, 225494)
	if err != nil {
		t.Fatal(err)
	}

	verifyAfterUTXOBlock1(t, d, true)
	if err := checkColumn(d, cfTransactions, []keyPair{}); err != nil {
		{
			t.Fatal(err)
		}
	}

}

func Test_findAndRemoveUnspentAddr(t *testing.T) {
	type args struct {
		unspentAddrs string
		vout         uint32
	}
	tests := []struct {
		name  string
		args  args
		want  string
		want2 string
	}{
		{
			name: "3",
			args: args{
				unspentAddrs: "029c0010517a0115887452870212709393588893935687040e64635167006868060e76519351880087080a7b7b0115870a3276a9144150837fb91d9461d6b95059842ab85262c2923f88ac0c08636751680e04578710029112026114",
				vout:         3,
			},
			want:  "64635167006868",
			want2: "029c0010517a0115887452870212709393588893935687040e76519351880087080a7b7b0115870a3276a9144150837fb91d9461d6b95059842ab85262c2923f88ac0c08636751680e04578710029112026114",
		},
		{
			name: "10",
			args: args{
				unspentAddrs: "029c0010517a0115887452870212709393588893935687040e64635167006868060e76519351880087080a7b7b0115870a3276a9144150837fb91d9461d6b95059842ab85262c2923f88ac0c08636751680e04578710029112026114",
				vout:         10,
			},
			want:  "61",
			want2: "029c0010517a0115887452870212709393588893935687040e64635167006868060e76519351880087080a7b7b0115870a3276a9144150837fb91d9461d6b95059842ab85262c2923f88ac0c08636751680e04578710029112",
		},
		{
			name: "not there",
			args: args{
				unspentAddrs: "029c0010517a0115887452870212709393588893935687040e64635167006868060e76519351880087080a7b7b0115870a3276a9144150837fb91d9461d6b95059842ab85262c2923f88ac0c08636751680e04578710029112026114",
				vout:         11,
			},
			want:  "",
			want2: "029c0010517a0115887452870212709393588893935687040e64635167006868060e76519351880087080a7b7b0115870a3276a9144150837fb91d9461d6b95059842ab85262c2923f88ac0c08636751680e04578710029112026114",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := hex.DecodeString(tt.args.unspentAddrs)
			if err != nil {
				panic(err)
			}
			got, got2 := findAndRemoveUnspentAddr(b, tt.args.vout)
			h := hex.EncodeToString(got)
			if !reflect.DeepEqual(h, tt.want) {
				t.Errorf("findAndRemoveUnspentAddr() got = %v, want %v", h, tt.want)
			}
			h2 := hex.EncodeToString(got2)
			if !reflect.DeepEqual(h2, tt.want2) {
				t.Errorf("findAndRemoveUnspentAddr() got2 = %v, want %v", h2, tt.want2)
			}
		})
	}
}

func Test_unpackBlockAddresses(t *testing.T) {
	type args struct {
		buf string
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr bool
	}{
		{
			name: "1",
			args: args{"029c10517a011588745287127093935888939356870e646351670068680e765193518800870a7b7b0115873276a9144150837fb91d9461d6b95059842ab85262c2923f88ac08636751680457870291"},
			want: []string{"9c", "517a011588745287", "709393588893935687", "64635167006868", "76519351880087", "7b7b011587", "76a9144150837fb91d9461d6b95059842ab85262c2923f88ac", "63675168", "5787", "91"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := hex.DecodeString(tt.args.buf)
			if err != nil {
				panic(err)
			}
			got, err := unpackBlockAddresses(b)
			if (err != nil) != tt.wantErr {
				t.Errorf("unpackBlockAddresses() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			h := make([]string, len(got))
			for i, g := range got {
				h[i] = hex.EncodeToString(g)
			}
			if !reflect.DeepEqual(h, tt.want) {
				t.Errorf("unpackBlockAddresses() = %v, want %v", got, tt.want)
			}
		})
	}
}