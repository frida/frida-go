package main

import (
	"bufio"
	"fmt"
	"os"
	"time"

	"github.com/lateralusd/frida-go/frida"
)

func main() {
	mon := frida.NewFileMonitor("/tmp/test.txt")
	if err := mon.Enable(); err != nil {
		panic(err)
	}

	mon.On("change", func(changedFile, otherFile, changeType string) {
		fmt.Printf("[*] File %s has changed (%s)\n", changedFile, changeType)
	})

	fmt.Printf("[*] Monitoring path: %s\n", mon.Path())

	t := time.NewTimer(20 * time.Second)
	<-t.C

	if err := mon.Disable(); err != nil {
		panic(err)
	}

	r := bufio.NewReader(os.Stdin)
	r.ReadLine()
}
