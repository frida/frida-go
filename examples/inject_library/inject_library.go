package main

import (
	"bufio"
	"fmt"
	"os"

	"github.com/lateralusd/frida-go/frida"
)

var sc = `
console.log("Hello from JavaScript");

rpc.exports = {
	add(a, b) {
	  return a + b;
	},
	whoami() {
		console.log("I am erhad");
	}
};
`

func main() {
	d := frida.LocalDevice()

	id, err := d.InjectLibraryFile("Telegram", "./lib.dylib", "new_one", "erhad")
	if err != nil {
		panic(err)
	}
	_ = id

	sess, err := d.Attach("Telegram", nil)
	if err != nil {
		panic(err)
	}

	script, err := sess.CreateScript(sc)
	if err != nil {
		panic(err)
	}

	script.On("message", func(message string) {
		fmt.Println("Received", message)
	})

	script.Load()

	fmt.Println("Ret for add", script.ExportsCall("add", 1, 2))
	fmt.Println("Ret for whoami", script.ExportsCall("whoami"))

	r := bufio.NewReader(os.Stdin)
	r.ReadLine()
}
