package main

import (
	"bufio"
	"fmt"
	"github.com/lateralusd/frida-go/frida"
	"os"
)

func main() {
	session, err := frida.Attach(0)
	if err != nil {
		panic(err)
	}

	compiled, err := session.CompileScript(
		`console.log("Hello")`, nil)
	if err != nil {
		panic(err)
	}

	script, err := session.CreateScriptBytes(compiled, nil)
	if err != nil {
		panic(err)
	}
	script.On("message", func(message string) {
		fmt.Println("Got", message)
	})
	script.Load()

	r := bufio.NewReader(os.Stdin)
	r.ReadLine()
}
