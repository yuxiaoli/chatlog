package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/sjzar/chatlog/internal/wechat/decrypt"
	"github.com/sjzar/chatlog/internal/wechat/key"
	"github.com/sjzar/chatlog/internal/wechat/model"
)

type cachedAccount struct {
	Account     string `json:"account"`
	Platform    string `json:"platform"`
	Version     int    `json:"version"`
	FullVersion string `json:"full_version"`
	DataDir     string `json:"data_dir"`
	DataKey     string `json:"data_key"`
	ImgKey      string `json:"img_key,omitempty"`
}

type cachedConfig struct {
	LastAccount string          `json:"last_account"`
	History     []cachedAccount `json:"history"`
}

func main() {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	pidsValue := flag.String("pids", "", "comma-separated WeChat process IDs")
	dataDir := flag.String("data-dir", "", "WeChat account data directory")
	account := flag.String("account", "", "WeChat account name")
	version := flag.Int("version", 3, "WeChat major version")
	fullVersion := flag.String("full-version", "", "WeChat full version")
	output := flag.String("output", "", "exclusive temporary config path")
	flag.Parse()

	if *pidsValue == "" || *dataDir == "" || *account == "" || *output == "" {
		fmt.Fprintln(os.Stderr, "pids, data-dir, account, and output are required")
		os.Exit(2)
	}
	validator, err := decrypt.NewValidator(model.PlatformWindows, *version, *dataDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "could not initialize key validation")
		os.Exit(1)
	}

	for _, value := range strings.Split(*pidsValue, ",") {
		pid64, parseErr := strconv.ParseUint(strings.TrimSpace(value), 10, 32)
		if parseErr != nil {
			continue
		}
		extractor, extractorErr := key.NewExtractor(model.PlatformWindows, *version)
		if extractorErr != nil {
			fmt.Fprintln(os.Stderr, "could not initialize key extraction")
			os.Exit(1)
		}
		extractor.SetValidate(validator)
		process := &model.Process{
			PID:          uint32(pid64),
			AccountName:  *account,
			Platform:     model.PlatformWindows,
			Version:      *version,
			FullVersion:  *fullVersion,
			DataDir:      *dataDir,
			Status:       model.StatusOnline,
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		dataKey, imgKey, extractErr := extractor.Extract(ctx, process)
		cancel()
		if extractErr != nil || dataKey == "" {
			fmt.Fprintf(os.Stderr, "PID %d did not yield a valid key\n", pid64)
			continue
		}

		config := cachedConfig{
			LastAccount: *account,
			History: []cachedAccount{{
				Account:     *account,
				Platform:    model.PlatformWindows,
				Version:     *version,
				FullVersion: *fullVersion,
				DataDir:     *dataDir,
				DataKey:     dataKey,
				ImgKey:      imgKey,
			}},
		}
		encoded, encodeErr := json.Marshal(config)
		if encodeErr != nil {
			fmt.Fprintln(os.Stderr, "could not encode temporary key config")
			os.Exit(1)
		}
		file, createErr := os.OpenFile(*output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if createErr != nil {
			fmt.Fprintln(os.Stderr, "could not create temporary key config")
			os.Exit(1)
		}
		_, writeErr := file.Write(encoded)
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			_ = os.Remove(*output)
			fmt.Fprintln(os.Stderr, "could not write temporary key config")
			os.Exit(1)
		}
		fmt.Printf("Recovered a validated key from PID %d.\n", pid64)
		return
	}

	fmt.Fprintln(os.Stderr, errors.New("no running WeChat process yielded a valid key"))
	os.Exit(1)
}
