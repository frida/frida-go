package main

import (
	"bufio"
	"fmt"
	"os"

	"github.com/lateralusd/frida-go/frida"
)

var embedScript = `const button = {
	color: 'blue',
};

function mutateButton() {
	button.color = 'red';
}
`

var warmupScript = "mutateButton();"

var testScript = `
console.log('Button before:', JSON.stringify(button));
mutateButton();
console.log('Button after:', JSON.stringify(button));
`

func main() {
	sess, err := frida.Attach(0)
	if err != nil {
		panic(err)
	}

	snapshot, err := sess.SnapshotScript(embedScript,
		frida.NewSnapshotOptions(warmupScript, frida.ScriptRuntimeV8))
	if err != nil {
		panic(err)
	}

	scriptOpts := frida.NewScriptOptions("testsc")
	scriptOpts.SetSnapshot(snapshot)
	scriptOpts.SetRuntime(frida.ScriptRuntimeV8)

	onMessage := func(msg string) {
		fmt.Println("Received", msg)
	}

	script, err := sess.CreateScriptWithOptions(testScript, scriptOpts)
	script.On("message", onMessage)
	script.Load()

	r := bufio.NewReader(os.Stdin)
	r.ReadLine()
}
