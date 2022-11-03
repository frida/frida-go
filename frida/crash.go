package frida

//#include <frida-core.h>
import "C"
import (
	"fmt"
	"unsafe"
)

// Crash represents crash of frida.
type Crash struct {
	crash *C.FridaCrash
}

// PID returns the process identifier oc.crashed application
func (c *Crash) PID() int {
	return int(C.frida_crash_get_pid(c.crash))
}

// ProcessName returns the name of the process that crashed
func (c *Crash) ProcessName() string {
	return C.GoString(C.frida_crash_get_process_name(c.crash))
}

// Summary returns the summary of the crash
func (c *Crash) Summary() string {
	return C.GoString(C.frida_crash_get_summary(c.crash))
}

// Report returns the report of the crash
func (c *Crash) Report() string {
	return C.GoString(C.frida_crash_get_report(c.crash))
}

// Params returns the parameters of the crash.
func (c *Crash) Params() map[string]interface{} {
	ht := C.frida_crash_get_parameters(c.crash)
	params := gHashTableToMap(ht)
	return params
}

// String returns string interpretation of the crash
func (c *Crash) String() string {
	return fmt.Sprintf("<FridaCrash>: <%p>", c.crash)
}

func (c *Crash) Clean() {
	clean(unsafe.Pointer(c.crash), unrefFrida)
}
