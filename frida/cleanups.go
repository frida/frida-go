package frida

//#include <frida-core.h>
import "C"
import (
	"unsafe"
)

type CleanupType string

const (
	CleanGError    CleanupType = "*GError"
	CleanPOD       CleanupType = "POD"
	CleanFridaType CleanupType = "NonPOD"
)

type cleanupFn func(unsafe.Pointer)

var cleanups = map[CleanupType]cleanupFn{
	CleanGError:    gErrorFree,
	CleanPOD:       unrefPOD,
	CleanFridaType: unrefFrida,
}

func gErrorFree(err unsafe.Pointer) {
	C.g_error_free((*C.GError)(err))
}

func unrefPOD(obj unsafe.Pointer) {
	C.g_object_unref((C.gpointer)(obj))
}

func unrefFrida(obj unsafe.Pointer) {
	C.frida_unref((C.gpointer)(obj))
}

func clean(obj unsafe.Pointer, cType CleanupType) {
	go func() {
		fn := cleanups[cType]
		if fn != nil {
			fn(obj)
		}
	}()
}
