package frida

//#include <frida-core.h>
import "C"

type ServiceInt interface {
}

/*
FridaService * frida_device_open_service_finish (FridaDevice * self,
GAsyncResult * result,
GError ** error);
FridaService * frida_device_open_service_sync (FridaDevice * self,
const gchar * address, GCancellable * cancellable, GError ** error);
*/

// Service represents Service from frida-core
type Service struct {
	service *C.FridaService
}
