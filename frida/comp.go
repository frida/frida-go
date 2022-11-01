package frida

/*#include <frida-core.h>
 */
import "C"
import "unsafe"

type Compiler struct {
	cc *C.FridaCompiler
}

func NewCompiler() *Compiler {
	mgr := getDeviceManager()
	cc := C.frida_compiler_new(mgr.manager)

	return &Compiler{cc}
}

func (c *Compiler) On(sigName string, fn interface{}) {
	connectClosure(unsafe.Pointer(c.cc), sigName, fn)
}

func (c *Compiler) Build(entrypoint string) (string, error) {
	entrypointC := C.CString(entrypoint)
	defer C.free(unsafe.Pointer(entrypointC))

	var err *C.GError
	ret := C.frida_compiler_build_sync(c.cc, entrypointC, nil, nil, &err)
	if err != nil {
		return "", &FridaError{err}
	}

	return C.GoString(ret), nil
}

func (c *Compiler) Watch(entrypoint string) error {
	entrypointC := C.CString(entrypoint)
	defer C.free(unsafe.Pointer(entrypointC))

	var err *C.GError
	C.frida_compiler_watch_sync(c.cc, entrypointC, nil, nil, &err)
	if err != nil {
		return &FridaError{err}
	}

	return nil
}
