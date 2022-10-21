package frida

//#include <frida-core.h>
import "C"
import (
	"unsafe"
)

// FridaScript represents the FridaScript from frida-core.
//
// It is the main structure responsible for starting and
// handling received messages.
type Script struct {
	sc *C.FridaScript
}

// On function connects specific signal to the callback function.
// When the signal gets trigerred, the callback function will be called
// with the parameters populated
func (f *Script) On(sigName string, fn interface{}) {
	connectClosure(unsafe.Pointer(f.sc), sigName, fn)
}

// Load fuction loads the script into the process
func (f *Script) Load() error {
	var err *C.GError
	C.frida_script_load_sync(f.sc, nil, &err)
	if err != nil {
		return &FridaError{err}
	}
	return nil
}

// Unload function unload previously loaded script
func (f *Script) Unload() error {
	var err *C.GError
	C.frida_script_unload_sync(f.sc, nil, &err)
	if err != nil {
		return &FridaError{err}
	}
	return nil
}

// Destroyed function returns whether the script previously loaded is destroyed (could be caused by unload)
func (f *Script) Destroyed() bool {
	destroyed := C.frida_script_is_destroyed(f.sc)
	if int(destroyed) == 1 {
		return true
	}
	return false
}

// Eternalize function will keep the script loaded even after deataching from the process
func (f *Script) Eternalize() error {
	var err *C.GError
	C.frida_script_eternalize_sync(f.sc, nil, &err)
	if err != nil {
		return &FridaError{err}
	}
	return nil
}

// EnableDebugger function enables debugging on the port specified
func (f *Script) EnableDebugger(port uint16) error {
	var err *C.GError
	C.frida_script_enable_debugger_sync(f.sc, C.guint16(port), nil, &err)
	if err != nil {
		return &FridaError{err}
	}

	return nil
}

// DisableDebugger function disables debugging
func (f *Script) DisableDebugger() error {
	var err *C.GError
	C.frida_script_disable_debugger_sync(f.sc, nil, &err)
	if err != nil {
		return &FridaError{err}
	}
	return nil
}
