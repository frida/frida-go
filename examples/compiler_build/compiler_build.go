package main

import (
	"fmt"
	"github.com/lateralusd/frida-go/frida"
	"os"
)

func main() {
	c := frida.NewCompiler()
	c.On("starting", func() {
		fmt.Println("[*] Starting compiler")
	})
	c.On("finished", func() {
		fmt.Println("[*] Compiler finished")
	})
	c.On("bundle", func(bundle string) {
		fmt.Printf("[*] Compiler bundle: %s\n",
			bundle)
	})
	c.On("diagnostics", func(diag string) {
		fmt.Printf("[*] Compiler diagnostics: %s\n", diag)
	})

	bundle, err := c.Build("agent.ts")
	if err != nil {
		panic(err)
	}
	os.WriteFile("_agent.js", []byte(bundle), os.ModePerm)
}
