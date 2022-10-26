package main

import (
	"bufio"
	"fmt"
	"os"

	"github.com/lateralusd/frida-go/frida"
)

var sc = `Interceptor.attach(Module.getExportByName(null, 'open'), {
	onEnter: function (args) {
	  send({
		type: 'open',
		path: Memory.readUtf8String(args[0])
	  });
	}
  });`

func main() {
	d := frida.GetLocalDevice()

	instrument := func(pid int) {
		fmt.Printf("✔ attach(pid={%d})\n", pid)
		sess, err := d.Attach(pid)
		if err != nil {
			panic(err)
		}

		sess.On("detached", func(reason frida.SessionDetachReason) {
			fmt.Printf("⚡ detached: pid={%d}, reason='{%s}'\n", pid, frida.SessionDetachReason(reason))
		})

		fmt.Printf("✔ enable_child_gating()\n")
		if err := sess.EnableChildGating(); err != nil {
			panic(err)
		}

		fmt.Printf("✔ create_script()\n")
		script, err := sess.CreateScript(sc)
		if err != nil {
			panic(err)
		}

		script.On("message", func(message string) {
			fmt.Printf("⚡ message: pid={%d}, payload={message['%s']}\n", pid, message)
		})

		fmt.Printf("✔ load()\n")
		script.Load()

		fmt.Printf("✔ resume(pid={%d})\n", pid)
		d.Resume(pid)
	}

	d.On("child-added", func(child *frida.Child) {
		fmt.Printf("⚡ child_added: {%d}, parent_pid: {%d}\n",
			child.GetPid(),
			child.GetPPid())
		instrument(int(child.GetPid()))
	})

	d.On("child-removed", func(child *frida.Child) {
		fmt.Printf("⚡ child_removed: {%v}\n", child.GetPid())
	})

	d.On("output", func(pid int, fd int, data []byte) {
		fmt.Printf("⚡ output: pid={%d}, fd={%d}, data={%s}\n",
			pid,
			fd,
			string(data))
	})

	fopts := frida.NewFridaSpawnOptions()
	fopts.SetArgv([]string{
		"/bin/sh",
		"-c",
		"cat /etc/hosts",
	})
	fopts.SetStdio(frida.FRIDA_STDIO_PIPE)

	fmt.Printf("✔ spawn(argv={%v})\n", fopts.GetArgv())
	pid, err := d.Spawn("/bin/sh", fopts)
	if err != nil {
		panic(err)
	}

	instrument(pid)

	r := bufio.NewReader(os.Stdin)
	r.ReadLine()
}
