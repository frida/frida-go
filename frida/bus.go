package frida

//#include <frida-core.h>
//#include <stdlib.h>
import "C"
import (
	"runtime"
	"unsafe"
)

// Bus represent bus used to communicate with the devices.
type Bus struct {
	bus *C.FridaBus
}

// IsDetached returns whether the bus is detached from the device or not.
func (b *Bus) IsDetached() bool {
	dt := C.int(C.frida_bus_is_detached(b.bus))
	return dt == 1
}

// Attach attaches on the device bus.
func (b *Bus) Attach() error {
	var err *C.GError
	C.frida_bus_attach_sync(b.bus, nil, &err)
	return handleGError(err)
}

// Post send(post) msg to the device.
func (b *Bus) Post(msg string, data []byte) {
	msgC := C.CString(msg)
	defer C.free(unsafe.Pointer(msgC))

	gBytesData := goBytesToGBytes(data)
	wrapper := &GBytesWrapper{ptr: gBytesData}

	runtime.SetFinalizer(wrapper, func(w *GBytesWrapper) {
		clean(unsafe.Pointer(w.ptr), unrefGObject)
		w.ptr = nil
	})
	C.frida_bus_post(b.bus, msgC, gBytesData)
	runtime.KeepAlive(wrapper)
}

// Clean will clean resources held by the bus.
func (b *Bus) Clean() {
	clean(unsafe.Pointer(b.bus), unrefFrida)
}

// On connects bus to specific signals. Once sigName is triggered,
// fn callback will be called with parameters populated.
//
// Signals available are:
//   - "detached" with callback as func() {}
//   - "message" with callback as func(message string, data []byte) {}
func (b *Bus) On(sigName string, fn any) {
	connectClosure(unsafe.Pointer(b.bus), sigName, fn)
}
