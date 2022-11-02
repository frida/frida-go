package frida

//#include <frida-core.h>
import "C"

// Process represents FridaProcess from frida-core
type Process struct {
	proc *C.FridaProcess
}

// PID returns the PID of FridaProcess
func (p *Process) PID() int {
	return int(C.frida_process_get_pid(p.proc))
}

// Name returns the name of FridaProcess
func (p *Process) Name() string {
	return C.GoString(C.frida_process_get_name(p.proc))
}

func (p *Process) Params() map[string]interface{} {
	ht := C.frida_process_get_parameters(p.proc)
	params := gHashTableToMap(ht)
	return params
}
