package frida

//#include <frida-core.h>
import "C"

import (
	"fmt"
)

// Application represents the main application installed on the device
type Application struct {
	application *C.FridaApplication
}

// GetIdentifier returns application bundle identifier
func (a *Application) GetIdentifier() string {
	return C.GoString(C.frida_application_get_identifier(a.application))
}

// GetName returns application name
func (a *Application) GetName() string {
	return C.GoString(C.frida_application_get_name(a.application))
}

// GetPid returns application PID or "-" if it could not be obtained when application is not running
func (a *Application) GetPid() int {
	return int(C.frida_application_get_pid(a.application))
}

// String() returns the string representation of Application printing identifier, name and pid
func (a *Application) String() string {
	return fmt.Sprintf("Identifier: %s Name: %s PID: %d", a.GetIdentifier(), a.GetName(), a.GetPid())
}

// Params return the application parameters, like version, path etc
func (a *Application) Params() map[string]interface{} {
	ht := C.frida_application_get_parameters(a.application)

	params := gHashTableToMap(ht)

	return params
}
