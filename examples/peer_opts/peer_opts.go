package main

import (
	"github.com/lateralusd/frida-go/frida"
)

func main() {
	r1 := frida.NewRelay("localhost1", "relay1User", "relay1Pass", frida.RelayKindTurnTcp)
	r2 := frida.NewRelay("localhost2", "relay2User", "relay2Pass", frida.RelayKindTurnTcp)
	r3 := frida.NewRelay("localhost3", "relay3User", "relay3Pass", frida.RelayKindTurnTcp)

	relays := []*frida.Relay{
		r1,
		r2,
		r3,
	}

	opts := frida.NewPeerOptions()
	opts.SetStunServer("localhost")

	for _, relay := range relays {
		opts.AddRelay(relay)
	}
}
