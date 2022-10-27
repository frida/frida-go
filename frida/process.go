package frida

//#include <frida-core.h>
import "C"

// FridaProcess represents FridaProcess from frida-core
type Process struct {
	proc *C.FridaProcess
}

// GetPid returns the PID of FridaProcess
func (p *Process) GetPid() int {
	return int(C.frida_process_get_pid(p.proc))
}

// GetName returns the name of FridaProcess
func (p *Process) GetName() string {
	return C.GoString(C.frida_process_get_name(p.proc))
}

func (p *Process) GetParams() map[string]interface{} {
	ht := C.frida_process_get_parameters(p.proc)
	params := gHashTableToMap(ht)
	return params
}
