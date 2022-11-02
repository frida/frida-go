package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/lateralusd/frida-go/frida"
)

type cmd struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

func main() {
	mgr := frida.NewDeviceManager()

	ropts := frida.NewRemoteDeviceOptions()
	ropts.SetToken("secret_token")

	fmt.Printf("Origin: %s\n", ropts.Origin())
	fmt.Printf("Token: %s\n", ropts.Token())
	fmt.Printf("Keepalive: %d\n", ropts.KeepAliveInterval())

	dev, err := mgr.AddRemoteDevice("localhost", ropts)
	if err != nil {
		panic(err)
	}

	procs, err := dev.EnumerateProcesses(frida.ScopeFull)
	if err != nil {
		panic(err)
	}

	for _, proc := range procs {
		fmt.Printf("[*] Process: %s => %d\n", proc.Name(), proc.PID())
	}

	bus := dev.Bus()
	bus.On("message", func(msg string) {
		var c cmd
		json.Unmarshal([]byte(msg), &c)
		switch c.Type {
		case "help":
			fmt.Printf("\n[*] Result for \"help\"\n")
			for k, v := range c.Data.(map[string]interface{}) {
				fmt.Printf("%s => %s\n", k, v)
			}
		case "list_channels":
			fmt.Printf("\n[*] Result for \"list_channels\"\n")
			for _, k := range c.Data.([]interface{}) {
				fmt.Printf("%s\n", k)
			}
		case "list_users":
			fmt.Printf("\n[*] Result for \"list_users\"\n")
			for _, k := range c.Data.([]interface{}) {
				fmt.Printf("%s\n", k)
			}
		case "register":
			fmt.Printf("\n[*] Result for \"register\"\n%s\n", c.Data)
		case "broadcast":
			fmt.Printf("\n[*] Server message: %s\n", c.Data)
		case "welcome":
			fmt.Println(c.Data)
		case "msg":
			mp := c.Data.(map[string]interface{})
			fmt.Printf("\n[*] Message from \"%s\": %s\n",
				mp["from"].(string),
				mp["content"].(string))
		case "channelMessage":
			mp := c.Data.(map[string]interface{})
			fmt.Printf("\n%s %s: %s\n",
				mp["channel"].(string),
				mp["from"].(string),
				mp["content"].(string))
		}
	})
	bus.Attach()

	r := bufio.NewReader(os.Stdin)
	name := "NA"

	type msg struct {
		From    string `json:"from"`
		User    string `json:"user"`
		Content string `json:"content"`
	}

	for {
		fmt.Printf("command(%s)> ", name)
		c, _, _ := r.ReadLine()
		splitted := strings.Split(string(c), " ")
		switch splitted[0] {
		case "help":
			c := cmd{
				Type: "help",
				Data: "",
			}
			d, _ := json.Marshal(c)
			bus.Post(string(d), nil)
		case "list_channels":
			c := cmd{
				Type: "list_channels",
				Data: "",
			}
			d, _ := json.Marshal(c)
			bus.Post(string(d), nil)
		case "list_users":
			c := cmd{
				Type: "list_users",
				Data: "",
			}
			d, _ := json.Marshal(c)
			bus.Post(string(d), nil)
		case "register":
			name = splitted[1]
			c := cmd{
				Type: "register",
				Data: splitted[1],
			}
			d, _ := json.Marshal(c)
			bus.Post(string(d), nil)
		case "msg":
			c := cmd{
				Type: "msg",
				Data: msg{
					From:    name,
					User:    splitted[1],
					Content: strings.Join(splitted[2:], " "),
				},
			}
			d, _ := json.Marshal(c)
			bus.Post(string(d), nil)
		case "join":
			c := cmd{
				Type: "join",
				Data: splitted[1],
			}
			d, _ := json.Marshal(c)
			bus.Post(string(d), nil)
		case "msgc":
			c := cmd{
				Type: "msgc",
				Data: map[string]interface{}{
					"from":    name,
					"channel": splitted[1],
					"content": strings.Join(splitted[2:], " "),
				},
			}
			d, _ := json.Marshal(c)
			bus.Post(string(d), nil)
		case "exit":
			os.Exit(1)
		}
	}
}
