package frida

//#include <frida-core.h>
import "C"

type SessionOptions struct {
	opts *C.FridaSessionOptions
}

func NewSessionOptions(realm Realm, persist_timeout uint) *SessionOptions {
	opts := C.frida_session_options_new()
	C.frida_session_options_set_realm(opts, C.FridaRealm(realm))
	C.frida_session_options_set_persist_timeout(opts, C.guint(persist_timeout))

	return &SessionOptions{opts}
}
