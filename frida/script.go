package frida

//#include <frida-core.h>
import "C"
import (
	"encoding/json"
	"reflect"
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

// On function connects specific signal to the callback function.
// When the signal gets trigerred, the callback function will be called
// with the parameters populated
func (f *Script) On(sigName string, fn interface{}) {
	f.fn = reflect.ValueOf(fn)
	connectClosure(unsafe.Pointer(f.sc), sigName, f.hijackFn)
}

// Load fuction loads the script into the process.
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

// IsDestroyed function returns whether the script previously loaded is destroyed (could be caused by unload)
func (f *Script) IsDestroyed() bool {
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

// Post sends post to the script.
func (f *Script) Post(jsonString string, data []byte) {
	jsonStringC := C.CString(jsonString)
	defer C.free(unsafe.Pointer(jsonStringC))

	arr, len := uint8ArrayFromByteSlice(data)
	gBytesData := C.g_bytes_new((C.gconstpointer)(unsafe.Pointer(arr)), C.gsize(len))
	defer clean(unsafe.Pointer(gBytesData), CleanPOD)

	C.frida_script_post(f.sc, jsonStringC, gBytesData)
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

// ExportsCall will try to call fn from the rpc.exports with args provided
func (f *Script) ExportsCall(fn string, args ...interface{}) interface{} {
	rpcData := newRpcCall(fn)

	var aIface []interface{}
	aIface = append(aIface, args...)

	rpc := []interface{}{}
	rpc = append(rpc, rpcData...)
	rpc = append(rpc, aIface)

	ch := make(chan interface{})
	rpcCalls.Store(rpcData[1], ch)

	bt, _ := json.Marshal(rpc)
	f.Post(string(bt), nil)

	ret := <-ch
	return ret
}

func getRpcIdFromMessage(message string) (string, interface{}, error) {
	unmarshalled := make(map[string]interface{})
	if err := json.Unmarshal([]byte(message), &unmarshalled); err != nil {
		return "", nil, err
	}

	var rpcId string
	var ret interface{}

	loopMap := func(mp map[string]interface{}) {
		for _, v := range mp {
			if reflect.ValueOf(v).Kind() == reflect.Slice {
				slc := v.([]interface{})
				rpcId = slc[1].(string)
				ret = slc[3]

			}
		}
	}
	loopMap(unmarshalled)

	return rpcId, ret, nil
}

func (f *Script) hijackFn(message string, data []byte) {
	if strings.Contains(message, "frida:rpc") {
		rpcId, ret, err := getRpcIdFromMessage(message)
		if err != nil {
			panic(err)
		}
		callerCh, ok := rpcCalls.Load(rpcId)
		if !ok {
			panic("rpc-id not found")
		}
		ch := callerCh.(chan interface{})
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

func newRpcCall(fnName string) []interface{} {
	id := uuid.New()
	dt := []interface{}{
		"frida:rpc",
		id.String()[:16],
		"call",
		fnName,
	}

	return dt
}
