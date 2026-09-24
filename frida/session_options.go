package frida

//#include <frida-core.h>
import "C"
import "unsafe"

// SessionOptions type is used to configure session
type SessionOptions struct {
	opts *C.FridaSessionOptions
}

// NewSessionOptions create new SessionOptions with the realm and
// timeout to persist provided
func NewSessionOptions(realm Realm, persistTimeout uint) *SessionOptions {
	opts := C.frida_session_options_new()
	C.frida_session_options_set_realm(opts, C.FridaRealm(realm))
	C.frida_session_options_set_persist_timeout(opts, C.guint(persistTimeout))

	return &SessionOptions{opts}
}

// Realm returns the realm of the options
func (s *SessionOptions) Realm() Realm {
	rlm := C.frida_session_options_get_realm(s.opts)
	return Realm(rlm)
}

// PersistTimeout returns the persist timeout of the script.s
func (s *SessionOptions) PersistTimeout() int {
	return int(C.frida_session_options_get_persist_timeout(s.opts))
}

// SetExceptor sets Frida's exception handling mode.
func (s *SessionOptions) SetExceptor(exceptor Exceptor) {
	C.frida_session_options_set_exceptor(s.opts, C.FridaExceptor(exceptor))
}

// SetExitMonitor enables or disables Frida's exit monitor.
func (s *SessionOptions) SetExitMonitor(enabled bool) {
	value := C.gboolean(0)
	if enabled {
		value = 1
	}
	C.frida_session_options_set_exit_monitor(s.opts, value)
}

// ExitMonitor reports whether Frida's exit monitor is enabled.
func (s *SessionOptions) ExitMonitor() bool {
	return C.frida_session_options_get_exit_monitor(s.opts) != 0
}

// Clean will clean the resources held by the session options.
func (s *SessionOptions) Clean() {
	clean(unsafe.Pointer(s.opts), unrefFrida)
}
