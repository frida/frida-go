package frida

//#include <frida-core.h>
import "C"

// FridaProcessLists represensts FridaProcessList from frida-core
type ProcessList struct {
	pList     *C.FridaProcessList
	processes []Process
}

// EnumerateProcesses will return the slice of FridaProcess
func (f *ProcessList) EnumerateProcesses() []Process {
	return f.processes
}
