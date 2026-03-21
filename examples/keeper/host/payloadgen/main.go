package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/stateless"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
)

type payload struct {
	ChainID uint64
	Block   *types.Block
	Witness *stateless.Witness
}

type extWitnessHexHeaders struct {
	Headers []hexutil.Bytes `json:"headers"`
	Codes   []hexutil.Bytes `json:"codes"`
	State   []hexutil.Bytes `json:"state"`
	Keys    []hexutil.Bytes `json:"keys"`
}

func parseBlockFlag(v string) (uint64, bool, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, false, errors.New("empty block")
	}
	if strings.EqualFold(v, "latest") {
		return 0, true, nil
	}
	if strings.HasPrefix(v, "0x") || strings.HasPrefix(v, "0X") {
		u, err := strconv.ParseUint(v[2:], 16, 64)
		if err != nil {
			return 0, false, err
		}
		return u, false, nil
	}
	u, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		return 0, false, err
	}
	return u, false, nil
}

func latestBlockNumber(ctx context.Context, client *rpc.Client, timeout time.Duration) (uint64, error) {
	var latestHex string
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := client.CallContext(callCtx, &latestHex, "eth_blockNumber"); err != nil {
		return 0, err
	}
	latest, err := hexutil.DecodeUint64(latestHex)
	if err != nil {
		return 0, err
	}
	return latest, nil
}

func chainID(ctx context.Context, client *rpc.Client, timeout time.Duration) (uint64, error) {
	var chainIDHex string
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := client.CallContext(callCtx, &chainIDHex, "eth_chainId"); err != nil {
		return 0, err
	}
	return hexutil.DecodeUint64(chainIDHex)
}

func decodeWitnessRLP(witnessAny json.RawMessage) ([]byte, error) {
	var witnessHex string
	if err := json.Unmarshal(witnessAny, &witnessHex); err == nil {
		return hexutil.Decode(witnessHex)
	}

	var extWitness stateless.ExtWitness
	if err := json.Unmarshal(witnessAny, &extWitness); err == nil {
		return rlp.EncodeToBytes(&extWitness)
	}

	var alt extWitnessHexHeaders
	if err := json.Unmarshal(witnessAny, &alt); err != nil {
		return nil, err
	}
	headers := make([]*types.Header, 0, len(alt.Headers))
	for i, hb := range alt.Headers {
		var h types.Header
		if err := rlp.DecodeBytes(hb, &h); err != nil {
			return nil, fmt.Errorf("decode witness header[%d] failed: %w", i, err)
		}
		headers = append(headers, &h)
	}
	extWitness = stateless.ExtWitness{
		Headers: headers,
		Codes:   alt.Codes,
		State:   alt.State,
		Keys:    alt.Keys,
	}
	return rlp.EncodeToBytes(&extWitness)
}

func payloadPath(outDir string, blockNum uint64) string {
	return filepath.Join(outDir, strconv.FormatUint(blockNum, 16)+"_payload.rlp")
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := fmt.Sprintf("%s.tmp.%d", path, time.Now().UnixNano())
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func generateOne(ctx context.Context, client *rpc.Client, timeout time.Duration, outDir string, chainID uint64, blockNum uint64, skipExisting bool) error {
	outPath := payloadPath(outDir, blockNum)
	if skipExisting {
		if st, err := os.Stat(outPath); err == nil && st.Size() > 0 {
			fmt.Printf("block=%s skip existing: %s\n", hexutil.EncodeUint64(blockNum), outPath)
			return nil
		}
	}

	blockTag := hexutil.EncodeUint64(blockNum)

	var rawBlockHex string
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	if err := client.CallContext(callCtx, &rawBlockHex, "debug_getRawBlock", blockTag); err != nil {
		cancel()
		return fmt.Errorf("debug_getRawBlock failed: %w", err)
	}
	cancel()
	blockBytes, err := hexutil.Decode(rawBlockHex)
	if err != nil {
		return fmt.Errorf("decode raw block failed: %w", err)
	}
	var rawBlock types.Block
	if err := rlp.DecodeBytes(blockBytes, &rawBlock); err != nil {
		return fmt.Errorf("rlp decode block failed: %w", err)
	}

	var witnessAny json.RawMessage
	callCtx, cancel = context.WithTimeout(ctx, timeout)
	if err := client.CallContext(callCtx, &witnessAny, "debug_executionWitness", blockTag); err != nil {
		cancel()
		return fmt.Errorf("debug_executionWitness failed: %w", err)
	}
	cancel()
	witnessRLP, err := decodeWitnessRLP(witnessAny)
	if err != nil {
		return fmt.Errorf("decode witness failed: %w", err)
	}

	var witness stateless.Witness
	if err := rlp.DecodeBytes(witnessRLP, &witness); err != nil {
		return fmt.Errorf("decode witness as stateless.Witness failed: %w", err)
	}

	p := payload{
		ChainID: chainID,
		Block:   &rawBlock,
		Witness: &witness,
	}
	encoded, err := rlp.EncodeToBytes(p)
	if err != nil {
		return fmt.Errorf("encode payload failed: %w", err)
	}
	if err := writeFileAtomic(outPath, encoded, 0o644); err != nil {
		return fmt.Errorf("write output failed: %w", err)
	}
	sizeMB := float64(len(encoded)) / (1024 * 1024)
	fmt.Printf("block=%s wrote payload: %s payload_size=%.2fM chain_id=%d\n", blockTag, outPath, sizeMB, chainID)
	return nil
}

func resolveStartBlock(ctx context.Context, client *rpc.Client, timeout time.Duration, startBlock uint64, isLatest bool) (uint64, error) {
	if !isLatest {
		return startBlock, nil
	}
	return latestBlockNumber(ctx, client, timeout)
}

func main() {
	var (
		rpcURL       string
		block        string
		outDir       string
		timeout      time.Duration
		follow       bool
		pollInterval time.Duration
		skipExisting bool
	)
	flag.StringVar(&rpcURL, "rpc", "http://127.0.0.1:8545", "Ethereum JSON-RPC URL (must enable debug namespace)")
	flag.StringVar(&block, "block", "latest", "Block number (decimal/hex) or latest")
	flag.StringVar(&outDir, "out-dir", "/data/stephen/ziren-shape-bin/geth/payloads", "Output directory")
	flag.DurationVar(&timeout, "timeout", 20*time.Second, "RPC timeout")
	flag.BoolVar(&follow, "follow", false, "Continuously generate payloads for new blocks")
	flag.DurationVar(&pollInterval, "poll-interval", 5*time.Second, "Polling interval when --follow is enabled")
	flag.BoolVar(&skipExisting, "skip-existing", true, "Skip generation when target file already exists")
	flag.Parse()

	if pollInterval <= 0 {
		fmt.Fprintln(os.Stderr, "invalid --poll-interval: must be > 0")
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	rpcClient, err := rpc.DialContext(ctx, rpcURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "rpc dial failed: %v\n", err)
		os.Exit(2)
	}
	defer rpcClient.Close()

	startBlock, isLatest, err := parseBlockFlag(block)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid --block: %v\n", err)
		os.Exit(2)
	}

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "create out dir failed: %v\n", err)
		os.Exit(8)
	}

	cid, err := chainID(ctx, rpcClient, timeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "eth_chainId failed: %v\n", err)
		os.Exit(4)
	}

	startBlock, err = resolveStartBlock(ctx, rpcClient, timeout, startBlock, isLatest)
	if err != nil {
		fmt.Fprintf(os.Stderr, "eth_blockNumber failed: %v\n", err)
		os.Exit(3)
	}

	if !follow {
		if err := generateOne(ctx, rpcClient, timeout, outDir, cid, startBlock, skipExisting); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(6)
		}
		return
	}

	nextBlock := startBlock
	fmt.Printf("follow mode started: chain_id=%d start_block=%s poll_interval=%s\n", cid, hexutil.EncodeUint64(nextBlock), pollInterval)

	for {
		select {
		case <-ctx.Done():
			fmt.Println("follow mode stopped")
			return
		default:
		}

		latest, err := latestBlockNumber(ctx, rpcClient, timeout)
		if err != nil {
			fmt.Fprintf(os.Stderr, "eth_blockNumber failed: %v\n", err)
			time.Sleep(pollInterval)
			continue
		}
		if nextBlock > latest {
			time.Sleep(pollInterval)
			continue
		}

		for nextBlock <= latest {
			if err := generateOne(ctx, rpcClient, timeout, outDir, cid, nextBlock, skipExisting); err != nil {
				fmt.Fprintf(os.Stderr, "block=%s error: %v\n", hexutil.EncodeUint64(nextBlock), err)
				time.Sleep(pollInterval)
				break
			}
			nextBlock++
		}
	}
}
