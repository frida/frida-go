package frida

//#include <frida-core.h>
import "C"
import (
	"unsafe"
)

// Session type represents the session with the device.
type Session struct {
	s *C.FridaSession
}

// IsDetached returns bool whether session is detached or not.
func (s *Session) IsDetached() bool {
	detached := C.frida_session_is_detached(s.s)
	if int(detached) == 1 {
		return true
	}
	return false
}

// Detach detaches the current session.
func (s *Session) Detach() error {
	var err *C.GError
	C.frida_session_detach_sync(s.s, nil, &err)
	if err != nil {
		return &FridaError{err}
	}
	return nil
}

// Resume resumes the current session.
func (s *Session) Resume() error {
	var err *C.GError
	C.frida_session_resume_sync(s.s, nil, &err)
	if err != nil {
		return &FridaError{err}
	}
	return nil
}

// EnableChildGating enables child gating on the session.
func (f *Session) EnableChildGating() error {
	var err *C.GError
	C.frida_session_enable_child_gating_sync(f.s, nil, &err)
	if err != nil {
		return &FridaError{err}
	}

	return nil
}

// DisableChildGating disables child gating on the session.
func (f *Session) DisableChildGating() error {
	var err *C.GError
	C.frida_session_disable_child_gating_sync(f.s, nil, &err)
	if err != nil {
		return &FridaError{err}
	}

	return nil
}

// Create script creates new string from the string provided.
func (f *Session) CreateScript(script string) (*Script, error) {
	return f.CreateScriptWithSnapshot(script, nil)
}

// TODO
func (f *Session) CreateScriptBytes(script []byte) (*Script, error) {
	return nil, nil
}

// TODO
func (f *Session) CompileScript(script string) ([]byte, error) {
	return nil, nil
}

// SnapshotScript creates snapshot from the script.
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

// CreateScriptWithSnapshot creates the script with the script options provided.
// Useful in cases where you previously created the snapshot.
func (f *Session) CreateScriptWithSnapshot(script string, opts *ScriptOptions) (*Script, error) {
	sc := C.CString(script)
	defer C.free(unsafe.Pointer(sc))

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

// SetupPeerConnection sets up peer (p2p) connection with peer options provided.
func (s *Session) SetupPeerConnection(opts *PeerOptions) error {
	var err *C.GError
	C.frida_session_setup_peer_connection_sync(s.s, opts.opts, nil, &err)
	if err != nil {
		return &FridaError{err}
	}
	return nil
}

// JoinPortal joins portal at the address with portal options provided.
func (f *Session) JoinPortal(address string, opts *PortalOptions) (*PortalMembership, error) {
	addrC := C.CString(address)
	defer C.free(unsafe.Pointer(addrC))

	var err *C.GError
	mem := C.frida_session_join_portal_sync(f.s, addrC, opts.opts, nil, &err)
	if err != nil {
		return nil, &FridaError{err}
	}

	return &PortalMembership{mem}, nil
}

func (f *Session) On(sigName string, fn interface{}) {
	connectClosure(unsafe.Pointer(f.s), sigName, fn)
}
