package frida

//#include <frida-core.h>
import "C"
import "fmt"

// FridaCrash represents crash of frida
type Crash struct {
	crash *C.FridaCrash
}

func (f *Crash) String() string {
	return fmt.Sprintf("<FridaCrash>: <%p>", f.crash)
}

// GetPid returns the process identifier of crashed application
func (f *Crash) Pid() int {
	return int(C.frida_crash_get_pid(f.crash))
}

// GetProcName returns the name of the process that crashed
func (f *Crash) ProcName() string {
	return C.GoString(C.frida_crash_get_process_name(f.crash))
}

// GetSummary returns the summary of the crash
func (f *Crash) Summary() string {
	return C.GoString(C.frida_crash_get_summary(f.crash))
}

// GetReport returns the report of the crash
func (f *Crash) Report() string {
	return C.GoString(C.frida_crash_get_report(f.crash))
}
