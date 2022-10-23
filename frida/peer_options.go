package frida

//#include <frida-core.h>
import "C"
import "unsafe"

type PeerOptions struct {
	opts *C.FridaPeerOptions
}

func NewPeerOptions(stunServer string, relays []*Relay) *PeerOptions {
	opts := C.frida_peer_options_new()

	stunC := C.CString(stunServer)
	defer C.free(unsafe.Pointer(stunC))
	C.frida_peer_options_set_stun_server(opts, stunC)

	for _, relay := range relays {
		C.frida_peer_options_add_relay(opts, relay.r)
	}

	return &PeerOptions{opts}
}
