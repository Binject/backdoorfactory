package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"io"
	"io/ioutil"
	"log"
	"path/filepath"
	"testing"

	"github.com/Binject/binjection/bj"
	"github.com/Binject/shellcode"
)

func Test_Tar_Elf_Inject_1(t *testing.T) {

	// init test shellcode repo
	repo := shellcode.NewRepo("test")
	config := &bj.BinjectConfig{Repo: repo, CodeCaveMode: false, InjectionMethod: bj.SilvioInject}

	// Open test tar file with uninjected Elf in it
	b, err := ioutil.ReadFile(filepath.Join("test", "testelf.tar"))
	if err != nil {
		t.Fatal(err)
	}
	buf := bytes.NewBuffer(b)
	wet, err := Inject(buf, config)
	if err != nil {
		t.Fatal(err)
	}
	// Open up resulting tar and check for injection
	tr := tar.NewReader(wet)
	for {
		// Read a file from input
		hdr, err := tr.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			t.Fatal(err)
		}
		f := hdr.FileInfo()
		if f.IsDir() {
			continue
		}
		if f.Name() == "static_ls" {
			data, err := ioutil.ReadAll(tr)
			if err != nil {
				t.Fatal(err)
			}
			data2, err := ioutil.ReadFile(filepath.Join("test", "static_ls_hello_injected"))
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Compare(data, data2) != 0 {
				log.Fatal("Results don't match")
			}
			break
		}
		log.Fatal("static_ls not found")
	}
}

func Test_Tgz_Elf_Inject_1(t *testing.T) {

	// init test shellcode repo
	repo := shellcode.NewRepo("test")
	config := &bj.BinjectConfig{Repo: repo, CodeCaveMode: false, InjectionMethod: bj.SilvioInject}

	// Open test tar file with uninjected Elf in it
	b, err := ioutil.ReadFile(filepath.Join("test", "testelf.tgz"))
	if err != nil {
		t.Fatal(err)
	}
	buf := bytes.NewBuffer(b)
	wet, err := Inject(buf, config)
	if err != nil {
		t.Fatal(err)
	}
	// Open up resulting tgz and check for injection
	zr, err := gzip.NewReader(wet)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	for {
		// Read a file from input
		hdr, err := tr.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			t.Fatal(err)
		}
		f := hdr.FileInfo()
		if f.IsDir() {
			continue
		}
		if f.Name() == "static_ls" {
			data, err := ioutil.ReadAll(tr)
			if err != nil {
				t.Fatal(err)
			}
			data2, err := ioutil.ReadFile(filepath.Join("test", "static_ls_hello_injected"))
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Compare(data, data2) != 0 {
				log.Fatal("Results don't match")
			}
			break
		}
		log.Fatal("static_ls not found")
	}
}

func Test_Zip_Elf_Inject_1(t *testing.T) {

	// init test shellcode repo
	repo := shellcode.NewRepo("test")
	config := &bj.BinjectConfig{Repo: repo, CodeCaveMode: false, InjectionMethod: bj.SilvioInject}

	// Open test tar file with uninjected Elf in it
	b, err := ioutil.ReadFile(filepath.Join("test", "testelf.zip"))
	if err != nil {
		t.Fatal(err)
	}
	buf := bytes.NewBuffer(b)
	wet, err := Inject(buf, config)
	if err != nil {
		t.Fatal(err)
	}
	// Open up resulting zip and check for injection
	zr, err := zip.NewReader(bytes.NewReader(wet.Bytes()), int64(wet.Len()))
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range zr.File {
		// Read a file from input
		if file.Mode().IsDir() {
			continue
		}
		if file.Name == "static_ls" {
			f, err := file.Open()
			if err != nil {
				t.Fatal(err)
			}
			data, err := ioutil.ReadAll(f)
			f.Close()
			if err != nil {
				t.Fatal(err)
			}
			data2, err := ioutil.ReadFile(filepath.Join("test", "static_ls_hello_injected"))
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Compare(data, data2) != 0 {
				log.Fatal("Results don't match")
			}
			break
		}
		log.Fatal("static_ls not found")
	}
}
