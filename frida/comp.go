package frida

/*#include <frida-core.h>
 */
import "C"
import (
	"reflect"
	"unsafe"
)

// CompilerOptions represent options passed to compiler to build/watch.
type CompilerOptions struct {
	c *C.FridaCompilerOptions
}

// NewCompilerOptions creates new compiler options.
func NewCompilerOptions() *CompilerOptions {
	c := C.frida_compiler_options_new()
	return &CompilerOptions{c: c}
}

// SetProjectRoot sets the project root, you would use this if your entrypoint
// script is in another directory besides the current one.
func (c *CompilerOptions) SetProjectRoot(projectRoot string) {
	pRoot := C.CString(projectRoot)
	defer C.free(unsafe.Pointer(pRoot))

	C.frida_compiler_options_set_project_root(c.c, pRoot)
}

// SetJSCompression allows you to choose compression for generated file.
func (c *CompilerOptions) SetJSCompression(compress JSCompressionType) {
	C.frida_compiler_options_set_compression(c.c, (C.FridaJsCompression)(compress))
}

// SetSourceMaps allows you to choose whether you want source maps included or omitted.
func (c *CompilerOptions) SetSourceMaps(sourceMaps SourceMaps) {
	C.frida_compiler_options_set_source_maps(c.c, (C.FridaSourceMaps)(sourceMaps))
}

// SetOutputFormat allows to dictate which output format.
func (c *CompilerOptions) SetOutputFormat(outputFormat OutputFormat) {
	C.frida_compiler_options_set_output_format(c.c, (C.FridaOutputFormat)(outputFormat))
}

// SetBundleFormat allows to choose bundle format.
func (c *CompilerOptions) SetBundleFormat(bundleFormat BundleFormat) {
	C.frida_compiler_options_set_bundle_format(c.c, (C.FridaBundleFormat)(bundleFormat))
}

// SetTypeCheckMode allows to set which type checking option to have while compiling.
func (c *CompilerOptions) SetTypeCheckMode(typeCheckMode TypeCheckMode) {
	C.frida_compiler_options_set_type_check(c.c, (C.FridaTypeCheckMode)(typeCheckMode))
}

// Compiler type is used to compile scripts.
type Compiler struct {
	cc *C.FridaCompiler
	fn reflect.Value
}

// NewCompiler creates new compiler.
func NewCompiler() *Compiler {
	mgr := getDeviceManager()
	cc := C.frida_compiler_new(mgr.getManager())

	return &Compiler{
		cc: cc,
	}
}

// Build builds the script from the entrypoint.
func (c *Compiler) Build(entrypoint string, opts *CompilerOptions) (string, error) {
	entrypointC := C.CString(entrypoint)
	defer C.free(unsafe.Pointer(entrypointC))

	var o *C.FridaBuildOptions = nil
	if opts != nil {
		o = (*C.FridaBuildOptions)(opts.c)
	}

	var err *C.GError
	ret := C.frida_compiler_build_sync(c.cc, entrypointC, o, nil, &err)
	return C.GoString(ret), handleGError(err)
}

// Watch watches for changes at the entrypoint and sends the "output" signal.
func (c *Compiler) Watch(entrypoint string, opts *CompilerOptions) error {
	entrypointC := C.CString(entrypoint)
	defer C.free(unsafe.Pointer(entrypointC))

	var o *C.FridaWatchOptions = nil
	if opts != nil {
		o = (*C.FridaWatchOptions)(opts.c)
	}

	var err *C.GError
	C.frida_compiler_watch_sync(c.cc, entrypointC, o, nil, &err)
	return handleGError(err)
}

// Clean will clean resources held by the compiler.
func (c *Compiler) Clean() {
	clean(unsafe.Pointer(c.cc), unrefFrida)
}

// On connects compiler to specific signals. Once sigName is triggered,
// fn callback will be called with parameters populated.
//
// Signals available are:
//   - "starting" with callback as func() {}
//   - "finished" with callback as func() {}
//   - "output" with callback as func(bundle string) {}
//   - "diagnostics" with callback as func(diag string) {}
//   - "file_changed" with callback as func() {}
func (c *Compiler) On(sigName string, fn any) {
	// hijack diagnostics and pass only text
	if sigName == "diagnostics" {
		c.fn = reflect.ValueOf(fn)
		connectClosure(unsafe.Pointer(c.cc), sigName, c.hijackFn)
	} else {
		connectClosure(unsafe.Pointer(c.cc), sigName, fn)
	}
}

func (c *Compiler) hijackFn(diag map[string]any) {
	text := diag["text"].(string)
	args := []reflect.Value{reflect.ValueOf(text)}
	c.fn.Call(args)
}
