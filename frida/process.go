package frida

//#include <frida-core.h>
import "C"

// FridaProcess represents FridaProcess from frida-core
type Process struct {
	proc *C.FridaProcess
}

// GetPid returns the PID of FridaProcess
func (f *Process) GetPid() int {
	return int(C.frida_process_get_pid(f.proc))
}

// GetName returns the name of FridaProcess
func (f *Process) GetName() string {
	return C.GoString(C.frida_process_get_name(f.proc))
}
