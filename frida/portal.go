package frida

//#include <frida-core.h>
import "C"
import "unsafe"

type Portal struct {
	portal *C.FridaPortalService
}

func NewPortal(clusterParams, controlParams *EndpointParameters) *Portal {
	p := C.frida_portal_service_new(clusterParams.params, controlParams.params)

	return &Portal{
		portal: p,
	}
}

func (p *Portal) On(sigName string, fn interface{}) {
	connectClosure(unsafe.Pointer(p.portal), sigName, fn)
}

func (p *Portal) Start() error {
	var err *C.GError
	C.frida_portal_service_start_sync(p.portal, nil, &err)
	if err != nil {
		return &FridaError{err}
	}
	return nil
}

func (p *Portal) Stop() error {
	var err *C.GError
	C.frida_portal_service_stop_sync(p.portal, nil, &err)
	if err != nil {
		return &FridaError{err}
	}
	return nil
}

func (p *Portal) Kick(connectionId uint) {
	C.frida_portal_service_kick(p.portal, C.guint(connectionId))
}

func (p *Portal) Post(connectionId uint, json string, data []byte) {
	jsonC := C.CString(json)
	defer C.free(unsafe.Pointer(jsonC))

	arr, len := uint8ArrayFromByteSlice(data)
	defer C.free(unsafe.Pointer(arr))
	gBytesData := C.g_bytes_new((C.gconstpointer)(unsafe.Pointer(arr)), C.gsize(len))
	defer clean(unsafe.Pointer(gBytesData), CleanPOD)

	C.frida_portal_service_post(p.portal, C.guint(connectionId), jsonC, gBytesData)
}

func (p *Portal) Narrowcast(tag, json string, data []byte) {
	tagC := C.CString(tag)
	defer C.free(unsafe.Pointer(tagC))

	jsonC := C.CString(json)
	defer C.free(unsafe.Pointer(jsonC))

	arr, len := uint8ArrayFromByteSlice(data)
	defer C.free(unsafe.Pointer(arr))
	gBytesData := C.g_bytes_new((C.gconstpointer)(unsafe.Pointer(arr)), C.gsize(len))
	defer clean(unsafe.Pointer(gBytesData), CleanPOD)

	C.frida_portal_service_narrowcast(p.portal, tagC, jsonC, gBytesData)
}

func (p *Portal) Broadcast(json string, data []byte) {
	jsonC := C.CString(json)
	defer C.free(unsafe.Pointer(jsonC))

	arr, len := uint8ArrayFromByteSlice(data)
	defer C.free(unsafe.Pointer(arr))
	gBytesData := C.g_bytes_new((C.gconstpointer)(unsafe.Pointer(arr)), C.gsize(len))
	defer clean(unsafe.Pointer(gBytesData), CleanPOD)

	C.frida_portal_service_broadcast(p.portal, jsonC, gBytesData)
}

func (p *Portal) EnumerateTags(connectionId uint) []string {
	var length C.gint
	tagsC := C.frida_portal_service_enumerate_tags(
		p.portal,
		C.guint(connectionId),
		&length)

	return cArrayToStringSlice(tagsC, C.int(length))
}

func (p *Portal) TagConnection(connectionId uint, tag string) {
	tagC := C.CString(tag)
	defer C.free(unsafe.Pointer(tagC))

	C.frida_portal_service_tag(p.portal, C.guint(connectionId), tagC)
}

func (p *Portal) UntagConnection(connectionId uint, tag string) {
	tagC := C.CString(tag)
	defer C.free(unsafe.Pointer(tagC))

	C.frida_portal_service_untag(p.portal, C.guint(connectionId), tagC)
}
