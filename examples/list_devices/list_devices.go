package main

import (
	"fmt"

	"github.com/lateralusd/frida-go/frida"
)

func main() {
	manager := frida.NewManager()
	devices, err := manager.EnumerateDevices()
	if err != nil {
		panic(err)
	}

	fmt.Printf("[*] Frida version: %s\n", frida.Version())
	fmt.Println("[*] Devices: ")
	for _, device := range devices {
		fmt.Printf("[*] Params for: %s (%s)\n", device.Name(), device.ID())
		if device.ID() != "socket" {
			for k, v := range device.Params() {
				fmt.Printf("\t%s => %v\n", k, v)
			}
		}
	}
}
