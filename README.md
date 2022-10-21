# frida-go
Go bindings for frida

# Installation
* `GO111MODULE` needs to be set to `on` or `auto`.
* Make sure to have latest `glib` installed which the currently is `2.68.0`.
* Download the _frida-core-devkit_ from the Frida releases [page](https://github.com/frida/frida/releases/) for you operating system and architecture.
* Extract the downloaded archive
* Copy _frida-core.h_ inside your systems include directory(inside /usr/local/include/) and _libfrida-core.a_(usually /usr/local/lib) inside your lib directory
* Getting frida-go:
   * MacOS: `CGO_CFLAGS="-isysroot $(xcrun --sdk macosx --show-sdk-path)" go get github.com/lateralusd/frida-go`
   * Linux: `go get github.com/lateralusd/frida-go`

To obtain the include path, you can use something like:  
```bash
$ echo | gcc -E -Wp,-v -
clang -cc1 version 12.0.0 (clang-1200.0.32.29) default target x86_64-apple-darwin20.3.0
ignoring nonexistent directory "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/local/include"
ignoring nonexistent directory "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/Library/Frameworks"
#include "..." search starts here:
#include <...> search starts here:
 /usr/local/include
 /Library/Developer/CommandLineTools/usr/lib/clang/12.0.0/include
 ```
 
 To obtain the location from where the dynamic libraries gets loaded:
 ```bash
 ld -v 2
@(#)PROGRAM:ld  PROJECT:ld64-609.8
BUILD 15:07:46 Dec 18 2020
configured to support archs: armv6 armv7 armv7s arm64 arm64e arm64_32 i386 x86_64 x86_64h armv6m armv7k armv7m armv7em
Library search paths:
	/usr/lib
	/usr/local/lib
Framework search paths:
	/Library/Frameworks/
	/System/Library/Frameworks/
```

# Small example
```golang
package main

import (
	"bufio"
	"fmt"
	"os"

	"github.com/lateralusd/frida-go/frida"
)

var script = `
Interceptor.attach(Module.getExportByName(null, 'open'), {
	onEnter(args) {
		const what = args[0].readUtf8String();
		console.log("[*] open(" + what + ")");
	}
});
Interceptor.attach(Module.getExportByName(null, 'close'), {
	onEnter(args) {
		console.log("close called");
	}
});
`

func main() {
	mgr := frida.NewManager()

	devices, err := mgr.EnumerateDevices()
	if err != nil {
		panic(err)
	}

	for _, d := range devices {
		fmt.Println("[*] Found device with id:", d.ID())
	}

	localDev, err := mgr.GetLocalDevice()
	if err != nil {
		fmt.Println("Could not get USB device: ", err)
		// Let's exit here because there is no point to do anything with nonexistent device
		os.Exit(1)
	}

	fmt.Println("[*] Chosen device: ", localDev.Name())

	fmt.Println("[*] Attaching to Twitter\"")
	session, err := localDev.Attach("Twitter")

	script, err := session.CreateScript(script)
	if err != nil {
		fmt.Println("Error ocurred creating script:", err)
	}

	script.On("message", func(msg string) {
		fmt.Println("[*] Received", msg)
	})

	if err := script.Load(); err != nil {
		fmt.Println("Error loading script:", err)
		os.Exit(1)
	}

	r := bufio.NewReader(os.Stdin)
	r.ReadLine()
}



```

Build and run it, output will look something like this:
```bash
$ go build example.go && ./example
[*] Found device with id: local
[*] Found device with id: socket
[*] Chosen device:  Local System
[*] Attaching to Twitter"
[*] Received {"type":"log","level":"info","payload":"close called"}
[*] Received {"type":"log","level":"info","payload":"close called"}
[*] Received {"type":"log","level":"info","payload":"[*] open(/var/folders/12/r9jwcyn16gs82k1vt0xfl7cm0000gn/T/maccatalyst.com.atebits.Tweetie2/TemporaryItems/NSIRD_Twitter_1mGUBd/fs_metrics_state)"}
[*] Received {"type":"log","level":"info","payload":"close called"}
[*] Received {"type":"log","level":"info","payload":"close called"}
```
