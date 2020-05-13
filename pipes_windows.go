// +build windows

package main

import (
	"bufio"
	"bytes"
	"io/ioutil"
	"log"
	"net"

	"github.com/Binject/binjection/bj"
	npipe "gopkg.in/natefinch/npipe.v2"
)

// MakePipe - Create a named pipe
func MakePipe(pipename string) string {
	return `\\.\pipe\` + pipename

}

// ListenPipeDry - Handle events on the dry pipe (dry=not yet injected)
func ListenPipeDry(pipename string, config *bj.BinjectConfig) {
	ln, err := npipe.Listen(pipename)
	if err != nil {
		log.Fatalf("Listen(%s) failed: %v", pipename, err)
	}

	for {
		conn, err := ln.Accept()
		if err == npipe.ErrClosed {
			return
		}
		if err != nil {
			log.Fatalf("Error accepting connection: %v", err)
		}
		go handleDryConnection(conn, config)
	}
}

// ListenPipeWet - Handle events on the wet pipe (wet=injected)
func ListenPipeWet(pipename string) {
	ln, err := npipe.Listen(pipename)
	if err != nil {
		log.Fatalf("Listen(%s) failed: %v", pipename, err)
	}

	for {
		conn, err := ln.Accept()
		if err == npipe.ErrClosed {
			return
		}
		if err != nil {
			log.Fatalf("Error accepting connection: %v", err)
		}
		go handleWetConnection(conn)
	}
}

var lastBytes []byte

func handleDryConnection(conn net.Conn, config *bj.BinjectConfig) {
	r := bufio.NewReader(conn)
	b, err := ioutil.ReadAll(r)
	if err != nil {
		log.Printf("Error reading from connection: %v", err)
		return
	}

	bb := bytes.NewBuffer(b)
	i, err := Inject(bb, config)
	if err != nil {
		log.Printf("Error injecting: %v", err)
		return
	}
	if i != nil {
		lastBytes = i.Bytes()
		log.Println("Set lastBytes: ", len(lastBytes))
	}
	if err := conn.Close(); err != nil {
		log.Printf("Error closing server side of connection: %v", err)
		return
	}
}

func handleWetConnection(conn net.Conn) {
	w := bufio.NewWriter(conn)
	_, err := w.Write(lastBytes)

	log.Println("Wrote wet bytes: ", len(lastBytes))

	if err != nil {
		log.Printf("Error on writing to pipe: %v", err)
		return
	}

	if err := conn.Close(); err != nil {
		log.Printf("Error closing server side of connection: %v", err)
		return
	}
	lastBytes = nil
}
