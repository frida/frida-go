package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/lateralusd/frida-go/frida"
)

type cmd struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

var usersConn = map[string]uint{}
var usersList = []string{}
var channelsUsers = map[string][]uint{}

var channels = []string{
	"#reverseengineering",
	"#frida",
	"#radare2",
}

var commands = map[string]string{
	"register":      "name",
	"list_channels": "N/A",
	"msg":           "userName content",
	"list_users":    "N/A",
	"join":          "channelName",
	"msgc":          "channelName content",
}

type msg struct {
	From    string `json:"from"`
	User    string `json:"user"`
	Content string `json:"content"`
}

func main() {
	fmt.Printf("[*] Frida version: %s\n", frida.Version())

	for _, chanName := range channels {
		channelsUsers[chanName] = []uint{}
	}

	cluster, err := frida.NewEndpointParameters(&frida.EParams{
		Address: "0.0.0.0",
		Port:    27052,
		//Token:   "staticToken",
		AuthenticationCallback: func(token string) string {
			if token == "secret_token" {
				return "thisIsSupposedToBeSomeRandomToken"
			}
			return ""
		},
		AssetRoot: "/Users/daemon1/",
	})

	if err != nil {
		panic(err)
	}

	control, err := frida.NewEndpointParameters(&frida.EParams{
		Address: "0.0.0.0",
		Port:    27042,
		//Token:   "staticToken",
		AuthenticationCallback: func(token string) string {
			if token == "secret_token" {
				return "thisIsSupposedToBeSomeRandomToken"
			}
			return ""
		},
		AssetRoot: "/Users/daemon1/",
	})

	portal := frida.NewPortal(cluster, control)
	if err := portal.Start(); err != nil {
		panic(err)
	}
	defer portal.Stop()

	clusterParams := portal.ClusterParams()
	controlParams := portal.ControlParams()

	fmt.Println("Cluster parameters")
	fmt.Printf("Address: %s\n", clusterParams.Address())
	fmt.Printf("Origin: %s\n", clusterParams.Origin())
	fmt.Printf("Port: %d\n", clusterParams.Port())
	fmt.Printf("Asset root: %s\n", clusterParams.AssetRoot())

	fmt.Println("Control parameters")
	fmt.Printf("Address: %s\n", controlParams.Address())
	fmt.Printf("Origin: %s\n", controlParams.Origin())
	fmt.Printf("Port: %d\n", controlParams.Port())
	fmt.Printf("Asset root: %s\n", controlParams.AssetRoot())

	portal.On("node_connected", func(connId uint, addr *frida.Address) {
		fmt.Printf("[*] Node connected: %s(connId=%d)\n", addr, connId)
	})

	portal.On("node_disconnected", func(connId uint, addr *frida.Address) {
		fmt.Printf("[*] Node disconnected: %s(connId=%d)\n", addr, connId)
	})

	portal.On("node_joined", func(connId uint, app *frida.Application) {
		fmt.Printf("[*] Node joined: %d with app: %s\n", connId, app.Name())
	})

	portal.On("node_left", func(connId uint, app *frida.Application) {
		fmt.Printf("[*] Node left: %d with app: %s\n", connId, app.Name())
	})

	portal.On("controller_connected", func(connId uint, addr *frida.Address) {
		fmt.Printf("[*] Controller connected: %s(connId=%d)\n", addr, connId)
	})

	portal.On("controller_disconnected", func(connId int, addr *frida.Address) {
		fmt.Printf("[*] Controller disconnected: %s(connId=%d)\n", addr, connId)
	})

	portal.On("authenticated", func(connId uint, sessionInfo string) {
		fmt.Printf("[*] Authenticated: %s(connId=%d)\n", sessionInfo, connId)
	})

	portal.On("subscribe", func(connId uint) {
		fmt.Printf("[*] Subscribed: connId=%d\n", connId)
		portal.Post(connId, `
		{
			"type": "welcome", 
			"data":"Welcome to Frida Portal"}
		`, nil)
	})

	portal.On("message", func(connId uint, jsonData string, data []byte) {
		var c cmd
		json.Unmarshal([]byte(jsonData), &c)
		switch c.Type {
		case "help":
			sendCommands(portal, connId)
		case "list_channels":
			sendChannels(portal, connId)
		case "list_users":
			sendUsers(portal, connId)
		case "register":
			registerUser(portal, connId, c.Data)
		case "msg":
			mp := c.Data.(map[string]interface{})
			user := mp["user"].(string)
			usConn, ok := usersConn[user]
			if ok {
				from := mp["from"]
				content := mp["content"]
				c := cmd{
					Type: "msg",
					Data: map[string]interface{}{
						"from":    from,
						"content": content,
					},
				}
				dt, _ := json.Marshal(c)
				portal.Post(usConn, string(dt), nil)
			}
		case "join":
			joinChannel(portal, connId, c.Data)
		case "msgc":
			mp := c.Data.(map[string]interface{})
			from := mp["from"]
			chName := mp["channel"]
			content := mp["content"]
			if exists := channelExists(chName.(string)); exists {
				c := cmd{
					Type: "channelMessage",
					Data: map[string]interface{}{
						"from":    from,
						"channel": chName,
						"content": content,
					},
				}
				dt, _ := json.Marshal(c)
				portal.Narrowcast(chName.(string), string(dt), nil)
			}
		}
	})

	go func() {
		t := time.NewTicker(5 * time.Minute)
		for {
			<-t.C
			c := cmd{
				Type: "broadcast",
				Data: "There will be server shutdown at 3.00AM",
			}
			dt, _ := json.Marshal(c)
			portal.Broadcast(string(dt), nil)
		}
	}()

	r := bufio.NewReader(os.Stdin)
	r.ReadLine()
}

func channelExists(chName string) bool {
	for _, chn := range channels {
		if chName == chn {
			return true
		}
	}
	return false
}

func sendCommands(portal *frida.Portal, connId uint) {
	c := cmd{
		Type: "help",
		Data: commands,
	}
	postData(portal, connId, &c)
}

func sendChannels(portal *frida.Portal, connId uint) {
	c := cmd{
		Type: "list_channels",
		Data: channels,
	}
	postData(portal, connId, &c)
}

func sendUsers(portal *frida.Portal, connId uint) {
	c := cmd{
		Type: "list_users",
		Data: usersList,
	}
	postData(portal, connId, &c)
}

func registerUser(portal *frida.Portal, connId uint, data interface{}) {
	usersConn[data.(string)] = connId
	usersList = append(usersList, data.(string))
	c := cmd{
		Type: "register",
		Data: fmt.Sprintf("Welcome %s", data.(string)),
	}
	postData(portal, connId, &c)
}

func joinChannel(portal *frida.Portal, connId uint, data interface{}) {
	chName := data.(string)
	channelsUsers[chName] = append(channelsUsers[chName], connId)
	portal.TagConnection(connId, chName)
}

func postData(portal *frida.Portal, connId uint, c *cmd) {
	data, _ := json.Marshal(c)
	portal.Post(connId, string(data), nil)
}
