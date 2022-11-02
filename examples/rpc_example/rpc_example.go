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
	add(a, b){
		return a + b;
	},
	hello(name) {
		console.log("Hello", name);
	}
}
`

func main() {
	d := frida.LocalDevice()

	sess, err := d.Attach("Telegram", nil)
	if err != nil {
		panic(err)
	}

	script, err := sess.CreateScript(sc)
	if err != nil {
		panic(err)
	}

	script.On("message", func(message string) {
		fmt.Println("Received message", message)
	})

	script.Load()

	addRes := script.ExportsCall("add", "1", "2")
	helloRes := script.ExportsCall("hello", "tkn")

	fmt.Println("Result for rpc add:", addRes)
	fmt.Println("Result for rpc hello:", helloRes)

	r := bufio.NewReader(os.Stdin)
	r.ReadLine()
}
