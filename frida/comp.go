package frida

/*#include <frida-core.h>
 */
import "C"
import "unsafe"

// Compiler type is used to compile scripts.
type Compiler struct {
	cc *C.FridaCompiler
}

// NewCompiler creates new compiler.
func NewCompiler() *Compiler {
	mgr := getDeviceManager()
	cc := C.frida_compiler_new(mgr.manager)

	return &Compiler{cc}
}

// Build builds the script from the entrypoint.
func (c *Compiler) Build(entrypoint string) (string, error) {
	entrypointC := C.CString(entrypoint)
	defer C.free(unsafe.Pointer(entrypointC))

	var err *C.GError
	ret := C.frida_compiler_build_sync(c.cc, entrypointC, nil, nil, &err)
	if err != nil {
		return "", &FError{err}
	}

	return C.GoString(ret), nil
}

// Watch watches for changes at the entrypoint and sends the "output" signal.
func (c *Compiler) Watch(entrypoint string) error {
	entrypointC := C.CString(entrypoint)
	defer C.free(unsafe.Pointer(entrypointC))

	var err *C.GError
	C.frida_compiler_watch_sync(c.cc, entrypointC, nil, nil, &err)
	if err != nil {
		return &FError{err}
	}

	return nil
}

// Clean will clean resources held by the compiler.
func (c *Compiler) Clean() {
	clean(unsafe.Pointer(c.cc), unrefFrida)
}

func (c *Compiler) On(sigName string, fn interface{}) {
	connectClosure(unsafe.Pointer(c.cc), sigName, fn)
}
