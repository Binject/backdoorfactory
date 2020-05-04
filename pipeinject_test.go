package main

import (
	"bytes"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Binject/binjection/bj"
)

func CompareFiles(file1, file2 string) bool {
	const chunkSize = 64 * 1024
	f1, err := os.Open(file1)
	if err != nil {
		log.Fatal(err)
	}
	f2, err := os.Open(file2)
	if err != nil {
		log.Fatal(err)
	}

	for {
		b1 := make([]byte, chunkSize)
		_, err1 := f1.Read(b1)

		b2 := make([]byte, chunkSize)
		_, err2 := f2.Read(b2)

		if err1 != nil || err2 != nil {
			if err1 == io.EOF && err2 == io.EOF {
				return true
			} else if err1 == io.EOF || err2 == io.EOF {
				return false
			} else {
				log.Fatal(err1, err2)
			}
		}

		if !bytes.Equal(b1, b2) {
			return false
		}
	}
}

func Test_Pipe_Elf_Inject_1(t *testing.T) {

	tmpDir := "./"
	//tmpDir, _ := ioutil.TempDir("", "named-pipes")
	namedPipe := filepath.Join(tmpDir, "bdf")

	dryPipe := MakePipe(namedPipe + "dry")
	wetPipe := MakePipe(namedPipe + "wet")

	config := &bj.BinjectConfig{CodeCaveMode: false}

	go ListenPipeDry(dryPipe, config)
	go ListenPipeWet(wetPipe)

	dryBytes, err := ioutil.ReadFile("test/static_ls")
	if err != nil {
		t.Fatal(err)
	}

	err = ioutil.WriteFile(dryPipe, dryBytes, 0555)
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(20 * time.Millisecond)

	wetBytes, err := ioutil.ReadFile(wetPipe)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Compare(dryBytes, wetBytes) != 0 {
		t.Log("Shellcode Injected Successfully!")
	} else {
		t.Fatal("Generated File Matched!")
	}

	t.Log("Lengths:", len(dryBytes), len(wetBytes))
	//t.Log(dryBytes, wetBytes)

	/*
		if !CompareFiles("test/ls_ptnote_hallo", "tmp/ls_ptnote_hallo.injected") {
			t.Error("Generated File Did Not Match!")
		} else {
			t.Log("Shellcode Injected Successfully!")
		}
	*/
}
