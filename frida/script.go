package frida

//#include <frida-core.h>
import "C"
import (
	"encoding/json"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"unsafe"

	"github.com/google/uuid"
)

var rpcCalls = &sync.Map{}

// Script represents loaded string in the memory.
type Script struct {
	sc *C.FridaScript
	fn reflect.Value
}

// IsDestroyed function returns whether the script previously loaded is destroyed (could be caused by unload)
func (f *Script) IsDestroyed() bool {
	destroyed := C.frida_script_is_destroyed(f.sc)
	return int(destroyed) == 1
}

// Load function loads the script into the process.
func (f *Script) Load() error {
	var err *C.GError
	C.frida_script_load_sync(f.sc, nil, &err)
	if err != nil {
		return &FError{err}
	}
	return nil
}

// Unload function unload previously loaded script
func (f *Script) Unload() error {
	var err *C.GError
	C.frida_script_unload_sync(f.sc, nil, &err)
	if err != nil {
		return &FError{err}
	}
	return nil
}

// Eternalize function will keep the script loaded even after deataching from the process
func (f *Script) Eternalize() error {
	var err *C.GError
	C.frida_script_eternalize_sync(f.sc, nil, &err)
	if err != nil {
		return &FError{err}
	}
	return nil
}

// Post sends post to the script.
func (f *Script) Post(jsonString string, data []byte) {
	jsonStringC := C.CString(jsonString)
	defer C.free(unsafe.Pointer(jsonStringC))

	gBytesData := goBytesToGBytes(data)
	runtime.SetFinalizer(gBytesData, func(g *C.GBytes) {
		clean(unsafe.Pointer(g), unrefGObject)
	})
	C.frida_script_post(f.sc, jsonStringC, gBytesData)
	runtime.KeepAlive(gBytesData)
}

// EnableDebugger function enables debugging on the port specified
func (f *Script) EnableDebugger(port uint16) error {
	var err *C.GError
	C.frida_script_enable_debugger_sync(f.sc, C.guint16(port), nil, &err)
	if err != nil {
		return &FError{err}
	}

	return nil
}

// DisableDebugger function disables debugging
func (f *Script) DisableDebugger() error {
	var err *C.GError
	C.frida_script_disable_debugger_sync(f.sc, nil, &err)
	if err != nil {
		return &FError{err}
	}
	return nil
}

// ExportsCall will try to call fn from the rpc.exports with args provided
func (f *Script) ExportsCall(fn string, args ...any) any {
	rpcData := newRPCCall(fn)

	var aIface []any
	aIface = append(aIface, args...)

	var rpc []any
	rpc = append(rpc, rpcData...)
	rpc = append(rpc, aIface)

	ch := make(chan any)
	rpcCalls.Store(rpcData[1], ch)

	bt, _ := json.Marshal(rpc)
	f.Post(string(bt), nil)

	ret := <-ch
	return ret
}

// Clean will clean the resources held by the script.
func (f *Script) Clean() {
	clean(unsafe.Pointer(f.sc), unrefFrida)
}

// On connects script to specific signals. Once sigName is triggered,
// fn callback will be called with parameters populated.
//
// Signals available are:
//   - "destroyed" with callback as func() {}
//   - "message" with callback as func(message string, data []byte) {}
func (f *Script) On(sigName string, fn any) {
	// hijack message to handle rpc calls
	if sigName == "message" {
		f.fn = reflect.ValueOf(fn)
		connectClosure(unsafe.Pointer(f.sc), sigName, f.hijackFn)
	} else {
		connectClosure(unsafe.Pointer(f.sc), sigName, fn)
	}
}

func getRPCIDFromMessage(message string) (string, any, error) {
	unmarshalled := make(map[string]any)
	if err := json.Unmarshal([]byte(message), &unmarshalled); err != nil {
		return "", nil, err
	}

	var rpcID string
	var ret any

	loopMap := func(mp map[string]any) {
		for _, v := range mp {
			if reflect.ValueOf(v).Kind() == reflect.Slice {
				slc := v.([]any)
				rpcID = slc[1].(string)
				ret = slc[3]

			}
		}
	}
	loopMap(unmarshalled)

	return rpcID, ret, nil
}

func (f *Script) hijackFn(message string, data []byte) {
	if strings.Contains(message, "frida:rpc") {
		rpcID, ret, err := getRPCIDFromMessage(message)
		if err != nil {
			panic(err)
		}
		callerCh, ok := rpcCalls.Load(rpcID)
		if !ok {
			panic("rpc-id not found")
		}
		ch := callerCh.(chan any)
		ch <- ret

	} else {
		var args []reflect.Value
		switch f.fn.Type().NumIn() {
		case 1:
			args = append(args, reflect.ValueOf(message))
		case 2:
			args = append(args, reflect.ValueOf(message))
			args = append(args, reflect.ValueOf(data))
		}
		f.fn.Call(args)
	}
}

func newRPCCall(fnName string) []any {
	id := uuid.New()
	dt := []any{
		"frida:rpc",
		id.String()[:16],
		"call",
		fnName,
	}

	return dt
}
