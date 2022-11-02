package main

import (
	"fmt"

	"github.com/lateralusd/frida-go/frida"
)

func main() {
	d := frida.USBDevice()
	if d == nil {
		fmt.Print("Device not found")
	}

	fma, err := d.FrontmostApplication(frida.ScopeFull)
	if err != nil {
		panic(err)
	}

	fmt.Println("[*] Frontmost application")
	fmt.Printf("[*] Name: %s\n", fma.Name())
	fmt.Printf("[*] Identifier: %s\n", fma.Identifier())
	fmt.Printf("[*] PID: %d\n", fma.PID())
	fmt.Printf("[*] Params: \n")
	p := fma.Params()

	var loopMap func(map[string]interface{})
	loopMap = func(mp map[string]interface{}) {
		for k, v := range mp {
			newMp, ok := v.(map[string]interface{})
			if !ok {
				_, ok := v.([]byte)
				if !ok {
					fmt.Printf("\t%s => %v\n", k, v)
				} else {
					fmt.Printf("\t%s => []byte{}\n", k)
				}
			} else {
				loopMap(newMp)
			}
		}
	}
	loopMap(p)
}
