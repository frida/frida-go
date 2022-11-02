package main

import (
	"bufio"
	"fmt"
	"os"

	"github.com/lateralusd/frida-go/frida"
)

func main() {
	r := bufio.NewReader(os.Stdin)
	dev := frida.USBDevice()
	channel, err := dev.OpenChannel("tcp:8080")
	if err != nil {
		panic(err)
	}
	defer channel.Close()

	dt := make([]byte, 512)
	read, err := channel.Read(&dt)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Got %s; %d bytes\n", string(dt), read)

	n, err := channel.Write([]byte("what's up"))
	if err != nil {
		panic(err)
	}
	fmt.Printf("Written %d bytes\n", n)

	r.ReadLine()
}
