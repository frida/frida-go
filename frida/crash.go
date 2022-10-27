package frida

//#include <frida-core.h>
import "C"
import "fmt"

// FridaCrash represents crash of frida
type Crash struct {
	crash *C.FridaCrash
}

// GetPid returns the process identifier oc.crashed application
func (c *Crash) GetPid() int {
	return int(C.frida_crash_get_pid(c.crash))
}

// GetProcessName returns the name of the process that crashed
func (c *Crash) GetProcessName() string {
	return C.GoString(C.frida_crash_get_process_name(c.crash))
}

// GetSummary returns the summary of the crash
func (c *Crash) GetSummary() string {
	return C.GoString(C.frida_crash_get_summary(c.crash))
}

// GetReport returns the report of the crash
func (c *Crash) GetReport() string {
	return C.GoString(C.frida_crash_get_report(c.crash))
}

// String returns string interpretation of the crash
func (c *Crash) String() string {
	return fmt.Sprintf("<FridaCrash>: <%p>", c.crash)
}
