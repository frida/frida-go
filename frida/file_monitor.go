package frida

//#include <frida-core.h>
import "C"

import "unsafe"

type FileMonitor struct {
	fm *C.FridaFileMonitor
}

func NewFileMonitor(path string) *FileMonitor {
	pathC := C.CString(path)
	defer C.free(unsafe.Pointer(pathC))

	m := C.frida_file_monitor_new(pathC)

	return &FileMonitor{
		fm: m,
	}
}

func (mon *FileMonitor) GetPath() string {
	return C.GoString(C.frida_file_monitor_get_path(mon.fm))
}

func (mon *FileMonitor) Enable() error {
	var err *C.GError
	C.frida_file_monitor_enable_sync(mon.fm, nil, &err)
	if err != nil {
		return &FridaError{err}
	}
	return nil
}

func (mon *FileMonitor) Disable() error {
	var err *C.GError
	C.frida_file_monitor_disable_sync(mon.fm, nil, &err)
	if err != nil {
		return &FridaError{err}
	}
	return nil
}

func (mon *FileMonitor) On(sigName string, fn interface{}) {
	connectClosure(unsafe.Pointer(mon.fm), sigName, fn)
}
