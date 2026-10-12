package frida

//#include <frida-core.h>
import "C"
import (
	"context"
	"encoding/json"
	"reflect"
	"runtime"
	"sync"
	"sync/atomic"
	"unsafe"
)

// Script represents loaded string in the memory.
type Script struct {
	sc                 *C.FridaScript
	messageHandlerOnce sync.Once
	messageHandler     atomic.Pointer[reflect.Value]
	pendingCalls       pendingScriptRPCCalls
}

// IsDestroyed function returns whether the script previously loaded is destroyed (could be caused by unload)
func (s *Script) IsDestroyed() bool {
	destroyed := C.frida_script_is_destroyed(s.sc)
	return int(destroyed) == 1
}

// Load function loads the script into the process.
func (s *Script) Load() error {
	s.ensureMessageHandler()
	var err *C.GError
	C.frida_script_load_sync(s.sc, nil, &err)
	return handleGError(err)
}

// Unload function unload previously loaded script
func (s *Script) Unload() error {
	var err *C.GError
	C.frida_script_unload_sync(s.sc, nil, &err)
	return handleGError(err)
}

// Eternalize function will keep the script loaded even after deataching from the process
func (s *Script) Eternalize() error {
	var err *C.GError
	C.frida_script_eternalize_sync(s.sc, nil, &err)
	return handleGError(err)
}

// Post sends post to the script.
func (s *Script) Post(jsonString string, data []byte) {
	jsonStringC := C.CString(jsonString)
	defer C.free(unsafe.Pointer(jsonStringC))

	if len(data) > 0 {
		gBytesData := goBytesToGBytes(data)
		wrapper := &GBytesWrapper{ptr: gBytesData}

		runtime.SetFinalizer(wrapper, func(w *GBytesWrapper) {
			clean(unsafe.Pointer(w.ptr), unrefGObject)
			w.ptr = nil
		})
		C.frida_script_post(s.sc, jsonStringC, gBytesData)
		runtime.KeepAlive(wrapper)
	} else {
		C.frida_script_post(s.sc, jsonStringC, nil)
	}
}

// EnableDebugger function enables debugging on the port specified
func (s *Script) EnableDebugger(port uint16) error {
	var err *C.GError
	C.frida_script_enable_debugger_sync(s.sc, C.guint16(port), nil, &err)

	return handleGError(err)
}

// DisableDebugger function disables debugging
func (s *Script) DisableDebugger() error {
	var err *C.GError
	C.frida_script_disable_debugger_sync(s.sc, nil, &err)
	return handleGError(err)
}

// ExportsCall will try to call fn from the rpc.exports with args provided
func (s *Script) ExportsCall(fn string, args ...any) any {
	return s.callExport(context.Background(), fn, args, s.postRPCRequest)
}

// ExportsCallWithContext will try to call fn from the rpc.exports with args provided using context provided.
func (s *Script) ExportsCallWithContext(ctx context.Context, fn string, args ...any) any {
	return s.callExport(ctx, fn, args, s.postRPCRequest)
}

func (s *Script) postRPCRequest(ctx context.Context, request scriptRPCRequest) error {
	message, err := json.Marshal(request)
	if err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ErrContextCancelled
	}
	s.Post(string(message), nil)
	return nil
}

// Clean will clean the resources held by the script.
func (s *Script) Clean() {
	clean(unsafe.Pointer(s.sc), unrefFrida)
}

// On connects script to specific signals. Once sigName is triggered,
// fn callback will be called with parameters populated.
//
// Signals available are:
//   - "destroyed" with callback as func() {}
//   - "message" with callback as func(message string, data []byte) {}
func (s *Script) On(sigName string, fn any) {
	if sigName == "message" {
		s.setMessageHandler(fn)
		s.ensureMessageHandler()
	} else {
		connectClosure(unsafe.Pointer(s.sc), sigName, fn)
	}
}

func (s *Script) ensureMessageHandler() {
	s.messageHandlerOnce.Do(func() {
		connectClosure(unsafe.Pointer(s.sc), "message", s.dispatchMessage)
	})
}

func (s *Script) setMessageHandler(fn any) {
	v := reflect.ValueOf(fn)
	if v.Kind() != reflect.Func {
		panic("got no function")
	}
	s.messageHandler.Store(&v)
}

func (s *Script) dispatchMessage(message string, data []byte) {
	if reply, isRPC := decodeScriptRPCReply(message); isRPC {
		if reply != nil {
			s.pendingCalls.complete(*reply)
		}
		return
	}
	fn := s.messageHandler.Load()
	if fn == nil {
		return
	}
	var args []reflect.Value
	switch fn.Type().NumIn() {
	case 1:
		args = append(args, reflect.ValueOf(message))
	case 2:
		args = append(args, reflect.ValueOf(message), reflect.ValueOf(data))
	}
	fn.Call(args)
}
