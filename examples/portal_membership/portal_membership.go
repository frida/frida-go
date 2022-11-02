package main

import (
	"bufio"
	"fmt"
	"os"

	"github.com/lateralusd/frida-go/frida"
)

func main() {
	session, err := frida.Attach(0)
	if err != nil {
		fmt.Print(err)
	}

	popts := frida.NewPortalOptions()
	popts.SetToken(os.Args[1])

	mem, err := session.JoinPortal("localhost", popts)
	if err != nil {
		panic(err)
	}

	fmt.Println(mem)

	r := bufio.NewReader(os.Stdin)
	r.ReadLine()
}
