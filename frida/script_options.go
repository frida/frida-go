package frida

//#include <frida-core.h>
//#include <glib.h>
import "C"
import "unsafe"

type ScriptOptions struct {
	opts *C.FridaScriptOptions
}

func NewScriptOptions(name string) *ScriptOptions {
	opts := C.frida_script_options_new()

	nameC := C.CString(name)
	defer C.free(unsafe.Pointer(nameC))

	C.frida_script_options_set_name(opts, nameC)

	return &ScriptOptions{
		opts: opts,
	}
}

func (f *ScriptOptions) SetSnapshot(value []byte) {
	arr, len := uint8ArrayFromByteSlice(value)
	defer C.free(unsafe.Pointer(arr))
	gBytesValue := C.g_bytes_new((C.gconstpointer)(unsafe.Pointer(arr)), C.gsize(len))
	defer clean(unsafe.Pointer(gBytesValue), CleanPOD)

	C.frida_script_options_set_snapshot(f.opts, gBytesValue)
}

func (f *ScriptOptions) SetRuntime(rt ScriptRuntime) {
	C.frida_script_options_set_runtime(f.opts, C.FridaScriptRuntime(rt))
}

func (f *ScriptOptions) SetName(name string) {
	nameC := C.CString(name)
	defer C.free(unsafe.Pointer(nameC))

	C.frida_script_options_set_name(f.opts, nameC)
}

func (f *ScriptOptions) GetName() string {
	return C.GoString(C.frida_script_options_get_name(f.opts))
}
