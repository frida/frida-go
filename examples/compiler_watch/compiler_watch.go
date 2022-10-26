package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"

	"github.com/lateralusd/frida-go/frida"
)

func main() {
	sess, err := frida.Attach(0)
	if err != nil {
		panic(err)
	}

	var script *frida.Script = nil

	onMessage := func(msg string) {
		msgMap := make(map[string]string)
		json.Unmarshal([]byte(msg), &msgMap)
		fmt.Printf("on_message: %s\n", msgMap["payload"])
	}

	compiler := frida.NewCompiler()
	compiler.On("output", func(bundle string) {
		if script != nil {
			fmt.Println("Unloading old bundle...")
			script.Unload()
			script = nil
		}
		fmt.Println("Loading bundle...")
		script, _ = sess.CreateScript(bundle)
		script.On("message", onMessage)
		script.Load()
	})

	compiler.Watch("agent.ts")

	r := bufio.NewReader(os.Stdin)
	r.ReadLine()
}
