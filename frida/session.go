package frida

//#include <frida-core.h>
import "C"
import (
	"unsafe"
)

type Session struct {
	s *C.FridaSession
}

func (f *Session) CreateScript(script string) (*Script, error) {
	return f.CreateScriptWithSnapshot(script, nil)
}

func (f *Session) CreateScriptWithSnapshot(script string, opts *ScriptOptions) (*Script, error) {
	sc := C.CString(script)
	defer objectFree(unsafe.Pointer(sc))

	if opts == nil {
		opts = NewScriptOptions("frida-go")
	}

	if opts.GetName() == "" {
		opts.SetName("frida-go")
	}

	var err *C.GError
	cScript := C.frida_session_create_script_sync(f.s, sc, opts.opts, nil, &err)
	if err != nil {
		return nil, &FridaError{err}
	}
	return &Script{
		sc: cScript,
	}, nil
}

func (f *Session) On(sigName string, fn interface{}) {
	connectClosure(unsafe.Pointer(f.s), sigName, fn)
}

// void frida_session_enable_child_gating_sync (FridaSession * self, GCancellable * cancellable, GError ** error);
func (f *Session) EnableChildGating() error {
	var err *C.GError
	C.frida_session_enable_child_gating_sync(f.s, nil, &err)
	if err != nil {
		return &FridaError{err}
	}

	return nil
}

// void frida_session_disable_child_gating_sync (FridaSession * self, GCancellable * cancellable, GError ** error);
func (f *Session) DisableChildGating() error {
	var err *C.GError
	C.frida_session_disable_child_gating_sync(f.s, nil, &err)
	if err != nil {
		return &FridaError{err}
	}

	return nil
}

func (f *Session) SnapshotScript(embedScript string, snapshotOpts *SnapshotOptions) ([]byte, error) {
	embedScriptC := C.CString(embedScript)
	defer C.free(unsafe.Pointer(embedScriptC))

	var err *C.GError
	ret := C.frida_session_snapshot_script_sync(
		f.s,
		embedScriptC,
		snapshotOpts.opts,
		nil,
		&err)

	if err != nil {
		return nil, &FridaError{err}
	}

	bts := getGBytes(ret)

	return bts, nil
}

func (f *Session) GetPortalMembership(address string, opts *PortalOptions) (*PortalMembership, error) {
	addrC := C.CString(address)
	defer C.free(unsafe.Pointer(addrC))

	var err *C.GError
	mem := C.frida_session_join_portal_sync(f.s, addrC, opts.opts, nil, &err)
	if err != nil {
		return nil, &FridaError{err}
	}

	return &PortalMembership{mem}, nil
}
