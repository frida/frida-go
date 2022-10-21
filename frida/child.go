package frida

//#include <frida-core.h>
import "C"

type Child struct {
	child *C.FridaChild
}

func (f *Child) GetPid() uint {
	return uint(C.frida_child_get_pid(f.child))
}

func (f *Child) GetPPid() uint {
	return uint(C.frida_child_get_parent_pid(f.child))
}

func (f *Child) GetOrigin() ChildOrigin {
	return ChildOrigin(C.frida_child_get_origin(f.child))
}

func (f *Child) GetIdentifier() string {
	return C.GoString(C.frida_child_get_identifier(f.child))
}

func (f *Child) GetPath() string {
	return C.GoString(C.frida_child_get_path(f.child))
}

func (f *Child) GetArgv() []string {
	var length C.gint
	arr := C.frida_child_get_argv(f.child, &length)

	return cArrayToStringSlice(arr, C.int(length))
}

func (f *Child) GetEnvp() []string {
	var length C.gint
	arr := C.frida_child_get_envp(f.child, &length)

	return cArrayToStringSlice(arr, C.int(length))
}
