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

var simpleScript = "console.log('Erhad');"

func main() {
	frida.Init()
	manager := frida.NewManager()

	fmt.Println("[*] Enumerating devices")
	devices, _ := manager.EnumerateDevices()
	for _, d := range devices {
		fmt.Println("[*] Found device with id:", d.GetID())
	}

	device, err := manager.GetLocalDevice()
	if err != nil {
		fmt.Println("Could not get USB device: ", err)
		// Let's exit here because there is no point to do anything with nonexistent device
		os.Exit(1)
	}
	fmt.Println("[*] Chosen device: ", device.GetName())

	pid := 31427
	fmt.Printf("[*] Attaching to %d\n", pid)
	session, err := device.Attach(pid)
	if err != nil {
		fmt.Println("Could not attach to", pid, ":", err)
	}
	fmt.Printf("[*] Session @%+v\n", session)

	script, err := session.CreateScript(script)
	if err != nil {
		fmt.Println("Error ocurred creating script:", err)
	}
	script.OnMessage(func(msg string) {
		fmt.Println("I have received", msg)
	})
	err = script.LoadScript()
	if err != nil {
		fmt.Println("Error loading script", err)
		os.Exit(1)
	}

	frida.RunLoop()
}


```

Build and run it, output will look something like this:
```bash
$ go build example.go && ./example
[*] Enumerating devices
[*] Found device with id: local
[*] Found device with id: socket
[*] Found device with id: 3f60e2688d3c6bebbdcb0871bf9abd33b55b6697
[*] Chosen device:  Local System
[*] Attaching to 31427
[*] Session @&{s:0xf0265c0}
I have received {"type":"log","level":"info","payload":"close called"}
I have received {"type":"log","level":"info","payload":"[*] open(/Users/daemon1/Library/Group Containers/group.com.atebits.Tweetie2/failed-compositions)"}
I have received {"type":"log","level":"info","payload":"close called"}
I have received {"type":"log","level":"info","payload":"close called"}
I have received {"type":"log","level":"info","payload":"[*] open(/Users/daemon1/Library/Containers/maccatalyst.com.atebits.Tweetie2/Data/Library/Caches/google-sdks-events/GDTCORFlatFileStorage/gdt_batch_data)"}
```
