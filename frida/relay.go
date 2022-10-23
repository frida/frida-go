package frida

//#include <frida-core.h>
import "C"
import "unsafe"

type Relay struct {
	r *C.FridaRelay
}

func NewRelay(address, username, password string, kind RelayKind) *Relay {
	/*
		FridaRelay * frida_relay_new (const gchar * address,
		const gchar * username,
		const gchar * password,
		FridaRelayKind kind);
	*/
	var addressC *C.char = nil
	var usernameC *C.char = nil
	var passwordC *C.char = nil

	if address != "" {
		addressC = C.CString(address)
		defer C.free(unsafe.Pointer(addressC))
	}

	if username != "" {
		usernameC = C.CString(username)
		defer C.free(unsafe.Pointer(usernameC))
	}

	if password != "" {
		passwordC = C.CString(password)
		defer C.free(unsafe.Pointer(passwordC))
	}

	knd := C.FridaRelayKind(kind)

	rly := C.frida_relay_new(
		addressC,
		usernameC,
		passwordC,
		knd)

	return &Relay{rly}
}

func (relay *Relay) GetAddress() string {
	return C.GoString(C.frida_relay_get_address(relay.r))
}

func (relay *Relay) GetUsername() string {
	return C.GoString(C.frida_relay_get_username(relay.r))
}

func (relay *Relay) GetPassword() string {
	return C.GoString(C.frida_relay_get_password(relay.r))
}

func (relay *Relay) GetRelayKind() RelayKind {
	return RelayKind(C.frida_relay_get_kind(relay.r))
}
