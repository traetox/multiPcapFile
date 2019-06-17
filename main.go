/*************************************************************************
 * Copyright 2018 Gravwell, Inc. All rights reserved.
 * Contact: <legal@gravwell.io>
 *
 * This software may be modified and distributed under the terms of the
 * BSD 2-clause license. See the LICENSE file for details.
 **************************************************************************/

package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/gravwell/ingest"
	"github.com/gravwell/ingest/entry"
	"github.com/gravwell/ingesters/args"
	"github.com/gravwell/ingesters/utils"
	"github.com/gravwell/ingesters/version"

	"github.com/google/gopacket"
	pcap "github.com/google/gopacket/pcapgo"
)

const (
	throwHintSize  uint64 = 1024 * 1024 * 16
	throwBlockSize int    = 16 * 1024
)

var (
	buffSize = flag.Int("file-buff-size", 16, "Size in megabytes for the file buffer")
	srcOvr   = flag.Uint64("source-override", 0, "Override source with an ID")
	status   = flag.Bool("status", false, "Output ingest rate stats as we go")
	fileinfo = flag.Bool("fileinfo", false, "Print file name as we process them")
	inFile   = flag.String("i", "", "Input file list to process")
	ver      = flag.Bool("v", false, "Print version and quit")

	pktCount    uint64
	pktSize     uint64
	simulate    bool
	fbuff       int
	srcOverride net.IP
)

func init() {
	flag.Parse()
	if *ver {
		version.PrintVersion(os.Stdout)
		ingest.PrintVersion(os.Stdout)
		os.Exit(0)
	}

	if *inFile == "" {
		log.Fatal("Input file path required")
	}
	//if not overriding, then make an empty has
	if *srcOvr == 0 {
		srcOverride = net.IP(make([]byte, 16))
	}
	if *buffSize <= 0 {
		fbuff = 4 * 1024 * 1024
	} else {
		fbuff = *buffSize * 1024 * 1024
	}
}

func main() {
	a, err := args.Parse()
	if err != nil {
		log.Fatalf("Invalid arguments: %v\n", err)
	}
	if len(a.Tags) != 1 {
		log.Fatal("File oneshot only accepts a single tag")
	}

	fin, err := os.Open(*inFile)
	if err != nil {
		log.Fatalf("Failed to open input file list %s: %v\n", *inFile, err)
	}

	//get a
	//fire up the ingesters
	igCfg := ingest.UniformMuxerConfig{
		Destinations: a.Conns,
		Tags:         a.Tags,
		Auth:         a.IngestSecret,
		PublicKey:    a.TLSPublicKey,
		PrivateKey:   a.TLSPrivateKey,
		LogLevel:     `INFO`,
	}
	igst, err := ingest.NewUniformMuxer(igCfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed build our ingest system: %v\n", err)
		return
	}
	if err := igst.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed start our ingest system: %v\n", err)
		return
	}
	if err := igst.WaitForHot(a.Timeout); err != nil {
		fmt.Fprintf(os.Stderr, "Timedout waiting for backend connections: %v\n", err)
		return
	}

	//get the TagID for our default tag
	tag, err := igst.GetTag(a.Tags[0])
	if err != nil {
		fmt.Printf("Failed to look up tag %s: %v\n", a.Tags[0], err)
		os.Exit(-1)
	}

	//listen for signals so we can close gracefully
	sch := make(chan os.Signal, 1)
	signal.Notify(sch, os.Interrupt)
	start := time.Now()

	//go ingest the file
	if err := doIngest(fin, igst, tag); err != nil {
		log.Fatalf("Failed to ingest file: %v\n", err)
	}

	if err := igst.Sync(10 * time.Second); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to sync: %v\n", err)
	}
	if err := igst.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to close ingester: %v\n", err)
	}
	dur := time.Since(start)
	fmt.Printf("Completed in %v (%s)\n", dur, ingest.HumanSize(pktSize))
	fmt.Printf("Total Count: %s\n", ingest.HumanCount(pktCount))
	fmt.Printf("Entry Rate: %s\n", ingest.HumanEntryRate(pktCount, dur))
	fmt.Printf("Ingest Rate: %s\n", ingest.HumanRate(pktSize, dur))
}

func doIngest(fin io.Reader, igst *ingest.IngestMuxer, tag entry.EntryTag) (err error) {
	//if not doing regular updates, just fire it off
	if !*status {
		err = ingestFiles(fin, igst, tag)
		return
	}

	errCh := make(chan error, 1)
	tckr := time.NewTicker(time.Second)
	defer tckr.Stop()
	go func(ch chan error) {
		ch <- ingestFiles(fin, igst, tag)
	}(errCh)

loop:
	for {
		lastts := time.Now()
		lastcnt := pktCount
		lastsz := pktSize
		select {
		case err = <-errCh:
			fmt.Println("\nDONE")
			break loop
		case _ = <-tckr.C:
			tdur := time.Since(lastts)
			cnt := pktCount - lastcnt
			bts := pktSize - lastsz
			fmt.Printf("\r%s %s                                     ",
				ingest.HumanEntryRate(cnt, tdur),
				ingest.HumanRate(bts, tdur))
		}
	}
	return
}

func ingestFiles(flist io.Reader, igst *ingest.IngestMuxer, tag entry.EntryTag) error {
	brdr := bufio.NewReader(flist)
	var i int
	for {
		i++
		ln, isPrefix, err := brdr.ReadLine()
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		if isPrefix {
			log.Printf("File list line %d is too long, skipping\n", i)
			continue
		}
		if *fileinfo {
			log.Println("Processing", string(ln))
		}
		fi, err := utils.OpenBufferedFileReader(string(ln), fbuff)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to open pcap file: %v\n", err)
			return err
		}
		hnd, err := pcap.NewReader(fi)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to open pcap Reader: %v\n", err)
			return err
		}

		if err = packetReader(hnd, igst, tag); err != nil {
			log.Printf("Failed to ingest %s: %v\n", ln, err)
			fi.Close()
			return err
		}

		if err = fi.Close(); err != nil {
			log.Printf("Failed to close %s: %v\n", ln, err)
		}
	}
	return nil
}

func packetReader(hnd *pcap.Reader, igst *ingest.IngestMuxer, tag entry.EntryTag) error {
	//get the src
	src, err := igst.SourceIP()
	if err != nil {
		return err
	}
	var sec int64
	var lSize uint64
	var ts entry.Timestamp
	var dt []byte
	var ci gopacket.CaptureInfo
	var blk []*entry.Entry

	//get packet src
	for {
		if dt, ci, err = hnd.ReadPacketData(); err != nil {
			if err == io.EOF {
				err = nil
			}
			break
		}
		ts = entry.FromStandard(ci.Timestamp)
		//check if we should throw
		if sec != ts.Sec || len(blk) >= throwBlockSize || lSize >= throwHintSize {
			if len(blk) > 0 {
				if err := igst.WriteBatch(blk); err != nil {
					return err
				}
				blk = nil
				lSize = 0
			}
		}
		blk = append(blk, &entry.Entry{
			TS:   ts,
			SRC:  src,
			Tag:  tag,
			Data: dt,
		})
		lSize += uint64(len(dt))
		sec = ts.Sec
		pktCount++
		pktSize += uint64(len(dt))
	}
	if len(blk) > 0 {
		if err := igst.WriteBatch(blk); err != nil {
			return err
		}
	}
	return nil
}
