package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/lateralusd/frida-go/frida"
)

var sc = `
var execPath = ObjC.classes.NSBundle.mainBundle().executablePath();
var dt = ObjC.classes.NSData.alloc().initWithContentsOfFile_(execPath);
var arr = Memory.readByteArray(dt.bytes(), dt.length());

send(execPath.toString(), arr);
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: dump_decrypted NAME")
		os.Exit(1)
	}

	target := os.Args[1]

	d := frida.USBDevice()
	session, err := d.Attach(target, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error attaching to target: %v\n", err)
		os.Exit(1)
	}

	script, err := session.CreateScript(sc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating script: %v\n", err)
		os.Exit(1)
	}

	var dumpedName string
	var length int
	done := make(chan struct{})
	script.On("message", func(message string, data []byte) {
		if len(data) > 0 {
			unmarshalled := make(map[string]string)
			json.Unmarshal([]byte(message), &unmarshalled)

			dumpedName = filepath.Base(unmarshalled["payload"])
			length = len(data)
			if err := ioutil.WriteFile(dumpedName, data, os.ModePerm); err != nil {
				fmt.Fprintf(os.Stderr, "Error saving binary: %v\n", err)
				os.Exit(1)
			}
		}
		done <- struct{}{}
	})
	script.Load()

	<-done
	fmt.Printf("[*] Saved \"%s\" (%d bytes)\n", dumpedName, length)
}
