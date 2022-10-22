package frida

/*
#include <frida-core.h>
#include <glib.h>

extern void onDetached(FridaSessionDetachReason reason, FridaCrash *crash);

static void call_dt(FridaSessionDetachReason reason, FridaCrash *crash) {
	onDetached(reason, crash);
}

static void on_detached (FridaSession * session, FridaSessionDetachReason reason, FridaCrash * crash, gpointer user_data)
{
	call_dt(reason, crash);
}

static void connect_session_detach(FridaSession *session) {
	g_signal_connect (session, "detached", G_CALLBACK (on_detached), NULL);
}

*/
import "C"
import (
	"unsafe"
)

type Session struct {
	s *C.FridaSession
}

func (f *Session) CreateScript(script string) (*Script, error) {
	return f.CreateScriptSnapshot(script, nil)
}

func (f *Session) CreateScriptSnapshot(script string, opts *ScriptOptions) (*Script, error) {
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
	return &Script{cScript}, nil
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
