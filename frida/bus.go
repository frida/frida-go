package frida

//#include <frida-core.h>
//#include <stdlib.h>
import "C"
import "unsafe"

// Bus represent bus used to communicate with the devices.
type Bus struct {
	bus *C.FridaBus
}

// IsDetached returns whether the bus is deteched from the device or not.
func (b *Bus) IsDetached() bool {
	dt := C.int(C.frida_bus_is_detached(b.bus))
	if dt == 1 {
		return true
	}
	return false
}

// Attach attaches on the device bus.
func (b *Bus) Attach() error {
	var err *C.GError
	C.frida_bus_attach_sync(b.bus, nil, &err)
	if err != nil {
		return &FridaError{err}
	}
	return nil
}

// Post send(post) data to the device.
func (b *Bus) Post(data string) {
	dataC := C.CString(data)
	defer C.free(unsafe.Pointer(dataC))

	C.frida_bus_post(b.bus, dataC, nil)
}

func (b *Bus) On(sigName string, fn interface{}) {
	connectClosure(unsafe.Pointer(b.bus), sigName, fn)
}
