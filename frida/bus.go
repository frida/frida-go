package frida

//#include <frida-core.h>
//#include <stdlib.h>
import "C"
import "unsafe"

type Bus struct {
	bus *C.FridaBus
}

func (b *Bus) On(sigName string, fn interface{}) {
	connectClosure(unsafe.Pointer(b.bus), sigName, fn)
}

func (b *Bus) Attach() error {
	var err *C.GError
	C.frida_bus_attach_sync(b.bus, nil, &err)
	if err != nil {
		return &FridaError{err}
	}
	return nil
}

func (b *Bus) Post(data string) {
	dataC := C.CString(data)
	defer C.free(unsafe.Pointer(dataC))

	C.frida_bus_post(b.bus, dataC, nil)
}

func (b *Bus) IsDetached() bool {
	dt := C.int(C.frida_bus_is_detached(b.bus))
	if dt == 1 {
		return true
	}
	return false
}
