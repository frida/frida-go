package frida

//#include <frida-core.h>
import "C"
import "unsafe"

// Child type represents child when child gating is enabled.
type Child struct {
	child *C.FridaChild
}

// GetPid returns the process id of the child.
func (f *Child) GetPid() uint {
	return uint(C.frida_child_get_pid(f.child))
}

// GetPPid returns the parent process id of the child.
func (f *Child) GetPPid() uint {
	return uint(C.frida_child_get_parent_pid(f.child))
}

// GetOrigin returns the origin of the child.
func (f *Child) GetOrigin() ChildOrigin {
	return ChildOrigin(C.frida_child_get_origin(f.child))
}

// GetIdentifier returns string identifier of the child.
func (f *Child) GetIdentifier() string {
	return C.GoString(C.frida_child_get_identifier(f.child))
}

// GetPath returns the path of the child.
func (f *Child) GetPath() string {
	return C.GoString(C.frida_child_get_path(f.child))
}

// GetArgv returns argv passed to the child.
func (f *Child) GetArgv() []string {
	var length C.gint
	arr := C.frida_child_get_argv(f.child, &length)

	return cArrayToStringSlice(arr, C.int(length))
}

// GetEnvp returns envp passed to the child.
func (f *Child) GetEnvp() []string {
	var length C.gint
	arr := C.frida_child_get_envp(f.child, &length)

	return cArrayToStringSlice(arr, C.int(length))
}

func (f *Child) Clean() {
	clean(unsafe.Pointer(f.child), unrefFrida)
}
