package frida

/*#include <frida-core.h>
#include <stdio.h>

extern void goEnumRelays(void * data, void *userData);

static void peer_enumerate_relays(void * data, void *user_data) {
	goEnumRelays(data, user_data);
}

static void call_enumerate(FridaPeerOptions * opts, void * fn) {
	frida_peer_options_enumerate_relays(opts, (GFunc)peer_enumerate_relays, (gpointer)fn);
}
*/
import "C"
import (
	"unsafe"
)

type PeerOptions struct {
	opts *C.FridaPeerOptions
}

func NewPeerOptions(stunServer string, relays []*Relay) *PeerOptions {
	opts := C.frida_peer_options_new()

	if stunServer != "" {
		stunC := C.CString(stunServer)
		defer C.free(unsafe.Pointer(stunC))
		C.frida_peer_options_set_stun_server(opts, stunC)
	}

	for _, relay := range relays {
		C.frida_peer_options_add_relay(opts, relay.r)
	}

	return &PeerOptions{opts}
}

func (p *PeerOptions) AddRelay(relay *Relay) {
	C.frida_peer_options_add_relay(p.opts, relay.r)
}

func (p *PeerOptions) SetStunServer(stunServer string) {
	stunC := C.CString(stunServer)
	defer C.free(unsafe.Pointer(stunC))
	C.frida_peer_options_set_stun_server(p.opts, stunC)
}

func (p *PeerOptions) GetStunServer() string {
	return C.GoString(C.frida_peer_options_get_stun_server(p.opts))
}

func (p *PeerOptions) ClearRelays() {
	C.frida_peer_options_clear_relays(p.opts)
}
