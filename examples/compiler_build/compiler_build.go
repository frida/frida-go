package main

import (
	"io/ioutil"
	"os"

	"github.com/lateralusd/frida-go/frida"
)

func main() {
	c := frida.NewCompiler()

	bundle, err := c.Build("agent.ts")
	if err != nil {
		panic(err)
	}
	ioutil.WriteFile("_agent.js", []byte(bundle), os.ModePerm)
}
