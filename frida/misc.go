package frida

//#include <frida-core.h>
import "C"

import (
	"fmt"
	"unsafe"
)

// FridaError holds a pointer to GError
type FridaError struct {
	error *C.GError
}

func (f *FridaError) Error() string {
	defer clean(unsafe.Pointer(f.error), unrefGError)
	return fmt.Sprintf("FridaError: %s", C.GoString(f.error.message))
}
