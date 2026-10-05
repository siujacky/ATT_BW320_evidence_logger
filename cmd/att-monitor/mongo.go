package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"attmonitor/internal/config"
	"attmonitor/internal/ledger"
	"attmonitor/internal/model"
	"attmonitor/internal/mongostore"
)

// cmdMongo handles `att-monitor mongo status | verify`: the MongoDB copy of the ledger
// (docs/DESIGN.md §17). The service keeps the copy up to date; these commands only read.
func cmdMongo(args []string) error {
	const usage = "usage: att-monitor mongo status | verify [--json] [--data DIR]"
	if len(args) == 0 {
		return errors.New(usage)
	}
	switch strings.ToLower(args[0]) {
	case "status":
		return cmdMongoStatus(args[1:])
	case "verify":
		return cmdMongoVerify(args[1:])
	}
	return fmt.Errorf("unknown mongo command %q (%s)", args[0], usage)
}

// mongoConfig loads the mongo section of the data directory's configuration.
func mongoConfig(dataDir string) (config.MongoConfig, error) {
	c, err := config.Load(config.PathsFor(dataDir).Config)
	if err != nil {
		return config.MongoConfig{}, fmt.Errorf("configuration: %w", err)
	}
	if !c.Mongo.Enabled {
		return c.Mongo, errors.New("the MongoDB copy is not enabled (mongo.enabled in config.json)")
	}
	return c.Mongo, nil
}

// cmdMongoStatus prints the state of the copy as the running service reports it.
func cmdMongoStatus(args []string) error {
	fs, data := newFlags("mongo status")
	asJSON := fs.Bool("json", false, "print the status as JSON")
	if err := fs.Parse(reorderArgs(args, "json")); err != nil {
		return err
	}
	dataDir := defaultDataDir(*data)
	api, ok := serviceAPI(dataDir)
	if !ok {
		mc, err := mongoConfig(dataDir)
		if err != nil {
			return err
		}
		fmt.Printf("The service is not running; it continues the copy into database %q at %s when it starts.\n",
			mc.Database, mongostore.RedactURI(mc.URI))
		return nil
	}
	var st model.Status
	if err := api.do(background(), http.MethodGet, "/api/status", nil, &st); err != nil {
		return err
	}
	if st.Mongo == nil {
		return errors.New("the running service has no MongoDB copy (mongo.enabled in config.json; restart the service after changing it)")
	}
	if *asJSON {
		return printJSON(st.Mongo)
	}
	m := st.Mongo
	state := "connected"
	if !m.Connected {
		state = "NOT CONNECTED (evidence recording is not affected; the copy catches up when MongoDB is back)"
	}
	fmt.Printf("MongoDB copy: database %q at %s — %s\n", m.Database, m.URI, state)
	if m.HasData {
		fmt.Printf("  copied up to record #%d of #%d (%d behind)\n", m.LastSeq, st.Ledger.HeadSeq, m.Lag)
	} else {
		fmt.Println("  nothing copied yet")
	}
	if m.Records > 0 || m.Blobs > 0 {
		fmt.Printf("  %d records, %d blobs\n", m.Records, m.Blobs)
	}
	if m.LastSync != "" {
		fmt.Println("  last pass:", m.LastSync)
	}
	if m.LastError != "" {
		fmt.Println("  last error:", m.LastError)
	}
	return nil
}

// cmdMongoVerify compares the MongoDB copy with the ledger record by record (read-only on both).
func cmdMongoVerify(args []string) error {
	fs, data := newFlags("mongo verify")
	asJSON := fs.Bool("json", false, "print the result as JSON")
	if err := fs.Parse(reorderArgs(args, "json")); err != nil {
		return err
	}
	dataDir := defaultDataDir(*data)
	mc, err := mongoConfig(dataDir)
	if err != nil {
		return err
	}
	st, err := ledger.Open(ledger.Options{
		Paths:    config.PathsFor(dataDir),
		ReadOnly: true,
		Logger:   slog.New(slog.DiscardHandler),
	})
	if err != nil {
		return err
	}
	defer st.Close()
	start := time.Now()
	res, err := mongostore.Verify(background(), mc.URI, mc.Database, st, st.PublicKey())
	if err != nil {
		return err
	}
	if *asJSON {
		if err := printJSON(res); err != nil {
			return err
		}
	} else {
		verdict := "PASSED"
		if !res.OK {
			verdict = "FAILED"
		}
		fmt.Printf("MongoDB copy verification %s — database %q at %s, %s\n", verdict, mc.Database,
			mongostore.RedactURI(mc.URI), time.Since(start).Round(time.Millisecond))
		fmt.Printf("  records: %d documents, %d compared with the ledger (same h, s and b; h = SHA-256(b); signature under key %s)\n",
			res.Records, res.Checked, ledger.FormatFingerprint(st.Fingerprint()))
		fmt.Printf("  missing %d, mismatched or not in the ledger %d, bad hash or signature %d\n", res.Missing, res.Mismatched, res.BadHash)
		if res.CopiedUpTo < 0 {
			fmt.Printf("  the copy holds no record yet (ledger head #%d)\n", res.LedgerHead)
		} else {
			fmt.Printf("  the copy reaches record #%d of #%d (%d not copied yet; the running service copies new records within seconds)\n",
				res.CopiedUpTo, res.LedgerHead, res.NotCopied)
		}
		fmt.Printf("  blobs: %d checked, %d missing, %d corrupt\n", res.BlobsChecked, res.BlobsMissing, res.BlobsCorrupt)
		for _, p := range res.Problems {
			fmt.Println("  PROBLEM:", p)
		}
	}
	if !res.OK {
		return exitCode(2)
	}
	return nil
}
