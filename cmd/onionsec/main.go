// Command onionsec is the CLI entry point.
//
// Usage:
//
//	onionsec scan <target.onion> [--json out.json] [--md out.md]
//	onionsec report <target.onion>          (re-render the latest saved scan)
//	onionsec monitor <target.onion>         (scan + diff against last run)
//	onionsec version
//
// See docs/ROADMAP.md for the CLI-first -> API -> dashboard phasing, and
// README.md for the authorized-use requirement before running this against
// any target.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/AryanXCode646/OnionScan/internal/crawler"
	"github.com/AryanXCode646/OnionScan/internal/model"
	"github.com/AryanXCode646/OnionScan/internal/report"
	"github.com/AryanXCode646/OnionScan/internal/scan"
	"github.com/AryanXCode646/OnionScan/internal/storage"
	"github.com/AryanXCode646/OnionScan/internal/tor"
)

const version = "0.1.0-dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "scan":
		cmdScan(os.Args[2:])
	case "report":
		cmdReport(os.Args[2:])
	case "monitor":
		cmdMonitor(os.Args[2:])
	case "version":
		fmt.Println("onionsec " + version)
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `onionsec - security observability for Tor onion services

Only scan targets you own or are authorized to test.

Usage:
  onionsec scan <target.onion>
  onionsec report <target.onion>
  onionsec monitor <target.onion>
  onionsec version`)
}

func cmdScan(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: onionsec scan <target.onion>")
		os.Exit(1)
	}
	target := model.Target{Onion: args[0], CreatedAt: time.Now()}

	client := tor.NewHTTPClient(tor.DefaultSOCKSAddr, 30*time.Second)
	store := storage.New(defaultDataDir())

	ctx, cancel := context.WithTimeout(context.Background(), crawler.DefaultLimits.TotalBudget+time.Minute)
	defer cancel()

	result, err := scan.Run(ctx, client, store, target, crawler.DefaultLimits)
	if err != nil {
		fmt.Fprintln(os.Stderr, "scan failed:", err)
		os.Exit(1)
	}

	printSummary(result)
	if err := report.WriteMarkdown(os.Stdout, result); err != nil {
		fmt.Fprintln(os.Stderr, "render report:", err)
		os.Exit(1)
	}
}

func cmdReport(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: onionsec report <target.onion>")
		os.Exit(1)
	}
	store := storage.New(defaultDataDir())
	result, ok, err := store.Latest(args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, "read history:", err)
		os.Exit(1)
	}
	if !ok {
		fmt.Fprintln(os.Stderr, "no saved scans for", args[0], "-- run `onionsec scan` first")
		os.Exit(1)
	}
	_ = report.WriteMarkdown(os.Stdout, result)
}

func cmdMonitor(args []string) {
	// TODO: tracked in issue "Phase 4: implement `onionsec monitor` diffing".
	// Should: run a new scan, load the previous scan via storage.Store,
	// diff finding IDs/evidence, and print NEW / REMOVED / CHANGED sections.
	fmt.Fprintln(os.Stderr, "onionsec monitor: not implemented yet -- see open issues")
	os.Exit(1)
}

func printSummary(r model.ScanResult) {
	fmt.Printf("Target:     %s\n", r.Target.Onion)
	fmt.Printf("Pages seen: %d\n", r.PagesSeen)
	fmt.Printf("Risk score: %d / 100\n\n", r.RiskScore)
}

func defaultDataDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".onionsec"
	}
	return home + "/.onionsec/scans"
}
