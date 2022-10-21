package frida

/*#include <frida-core.h>
#include <glib.h>
#include <glib-object.h>
#include <stdio.h>
#include <string.h>
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// Application represents the main application installed on the device
type Application struct {
	application *C.FridaApplication
}

// Clean will call frida_unref on application pointer
func (f *Application) Clean() {
	objectUnref(unsafe.Pointer(f.application))
}

// GetIdentifier returns application bundle identifier
func (a *Application) Identifier() string {
	return C.GoString(C.frida_application_get_identifier(a.application))
}

// GetName returns application name
func (a *Application) Name() string {
	return C.GoString(C.frida_application_get_name(a.application))
}

// GetPid returns application PID or "-" if it could not be obtained when application is not running
func (a *Application) Pid() int {
	return int(C.frida_application_get_pid(a.application))
}

// String() returns the string representation of Application printing identifier, name and pid
func (f *Application) String() string {
	return fmt.Sprintf("Identifier: %s Name: %s PID: %d", f.Identifier(), f.Name(), f.Pid())
}

func (f *Application) Params() map[string]interface{} {
	v, ok := appParams.Load(f)
	if !ok {
		return nil
	}
	return v.(map[string]interface{})
}

func (f *Application) getParams() {
	ht := C.frida_application_get_parameters(f.application)
	iter := C.GHashTableIter{}
	var key C.gpointer
	var val C.gpointer
	C.g_hash_table_iter_init(&iter, ht)

	data := make(map[string]interface{})

	hSize := int(C.g_hash_table_size(ht))

	if hSize >= 1 {
		found := 1
		for found == 1 {
			found = int(C.g_hash_table_iter_next(&iter, &key, &val))

			keyGo := C.GoString((*C.char)(unsafe.Pointer(key)))
			vValue := gPointerToGo(val)

			data[keyGo] = vValue
		}
	}

	appParams.Store(f, data)
}
