package frida

//#include <frida-core.h>
import "C"
import "unsafe"

type SnapshotOptions struct {
	opts *C.FridaSnapshotOptions
}

func NewSnapshotOptions(warmupScript string, rt ScriptRuntime) *SnapshotOptions {
	opts := C.frida_snapshot_options_new()
	warmupScriptC := C.CString(warmupScript)
	defer C.free(unsafe.Pointer(warmupScriptC))

	C.frida_snapshot_options_set_warmup_script(opts, warmupScriptC)
	C.frida_snapshot_options_set_runtime(opts, C.FridaScriptRuntime(rt))

	return &SnapshotOptions{
		opts: opts,
	}
}
