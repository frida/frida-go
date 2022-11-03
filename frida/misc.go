package frida

//#include <frida-core.h>
import "C"

import (
	"fmt"
	"unsafe"
)

// FError holds a pointer to GError
type FError struct {
	error *C.GError
}

func (f *FError) Error() string {
	defer clean(unsafe.Pointer(f.error), unrefGError)
	return fmt.Sprintf("FError: %s", C.GoString(f.error.message))
}
