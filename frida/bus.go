package frida

//#include <frida-core.h>
//#include <stdlib.h>
import "C"
import "unsafe"

type Bus struct {
	bus *C.FridaBus
}

func (f *Bus) Attach() {
}

func (f *Bus) Post(data string) {
	dataC := C.CString(data)
	defer C.free(unsafe.Pointer(dataC))

	C.frida_bus_post(f.bus, dataC, nil)
}

func (f *Bus) IsDetached() bool {
	dt := C.int(C.frida_bus_is_detached(f.bus))
	if dt == 1 {
		return true
	}
	return false
}
