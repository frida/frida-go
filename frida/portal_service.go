package frida

//#include <frida-core.h>
import "C"
import (
	"runtime"
	"unsafe"
)

// Portal represents portal to collect exposed gadgets and sessions.
type Portal struct {
	portal *C.FridaPortalService
}

// NewPortal creates new Portal from the EndpointParameters provided.
func NewPortal(clusterParams, controlParams *EndpointParameters) *Portal {
	p := C.frida_portal_service_new(clusterParams.params, controlParams.params)

	return &Portal{
		portal: p,
	}
}

// GetDevice returns portal device.
func (p *Portal) GetDevice() *Device {
	dev := C.frida_portal_service_get_device(p.portal)
	return &Device{dev}
}

// GetClusterParams returns the cluster parameters for the portal.
func (p *Portal) GetClusterParams() *EndpointParameters {
	params := C.frida_portal_service_get_cluster_params(p.portal)
	return &EndpointParameters{params}
}

// GetControlParams returns the control parameters for the portal.
func (p *Portal) GetControlParams() *EndpointParameters {
	params := C.frida_portal_service_get_control_params(p.portal)
	return &EndpointParameters{params}
}

// Start stars the portal.
func (p *Portal) Start() error {
	var err *C.GError
	C.frida_portal_service_start_sync(p.portal, nil, &err)
	if err != nil {
		return &FridaError{err}
	}
	return nil
}

// Stop stops the portal.
func (p *Portal) Stop() error {
	var err *C.GError
	C.frida_portal_service_stop_sync(p.portal, nil, &err)
	if err != nil {
		return &FridaError{err}
	}
	return nil
}

// Kick kicks the connection with connectionId provided.
func (p *Portal) Kick(connectionId uint) {
	C.frida_portal_service_kick(p.portal, C.guint(connectionId))
}

// Post posts the message to the connectionId with json string or bytes.
func (p *Portal) Post(connectionId uint, json string, data []byte) {
	jsonC := C.CString(json)
	defer C.free(unsafe.Pointer(jsonC))

	arr, len := uint8ArrayFromByteSlice(data)
	defer C.free(unsafe.Pointer(arr))

	gBytesData := C.g_bytes_new((C.gconstpointer)(unsafe.Pointer(arr)), C.gsize(len))
	runtime.SetFinalizer(gBytesData, func(g *C.GBytes) {
		clean(unsafe.Pointer(g), unrefGObject)
	})

	C.frida_portal_service_post(p.portal, C.guint(connectionId), jsonC, gBytesData)
	runtime.KeepAlive(gBytesData)
}

// Narrowcast sends the message to all controllers tagged with the tag.
func (p *Portal) Narrowcast(tag, json string, data []byte) {
	tagC := C.CString(tag)
	defer C.free(unsafe.Pointer(tagC))

	jsonC := C.CString(json)
	defer C.free(unsafe.Pointer(jsonC))

	arr, len := uint8ArrayFromByteSlice(data)
	defer C.free(unsafe.Pointer(arr))
	gBytesData := C.g_bytes_new((C.gconstpointer)(unsafe.Pointer(arr)), C.gsize(len))
	runtime.SetFinalizer(gBytesData, func(g *C.GBytes) {
		clean(unsafe.Pointer(g), unrefGObject)
	})

	C.frida_portal_service_narrowcast(p.portal, tagC, jsonC, gBytesData)
	runtime.KeepAlive(gBytesData)
}

// Broadcast sends the message to all controllers.
func (p *Portal) Broadcast(json string, data []byte) {
	jsonC := C.CString(json)
	defer C.free(unsafe.Pointer(jsonC))

	arr, len := uint8ArrayFromByteSlice(data)
	defer C.free(unsafe.Pointer(arr))
	gBytesData := C.g_bytes_new((C.gconstpointer)(unsafe.Pointer(arr)), C.gsize(len))
	runtime.SetFinalizer(gBytesData, func(g *C.GBytes) {
		clean(unsafe.Pointer(g), unrefGObject)
	})

	C.frida_portal_service_broadcast(p.portal, jsonC, gBytesData)
	runtime.KeepAlive(gBytesData)
}

// EnumerateTags returns all the tags that connection with connectionId is tagged
// with.
func (p *Portal) EnumerateTags(connectionId uint) []string {
	var length C.gint
	tagsC := C.frida_portal_service_enumerate_tags(
		p.portal,
		C.guint(connectionId),
		&length)

	return cArrayToStringSlice(tagsC, C.int(length))
}

// TagConnection tags the connection with connectionId with the tag provided.
func (p *Portal) TagConnection(connectionId uint, tag string) {
	tagC := C.CString(tag)
	defer C.free(unsafe.Pointer(tagC))

	C.frida_portal_service_tag(p.portal, C.guint(connectionId), tagC)
}

// UntagConnection untags the connection with connectionId with the tag provided.
func (p *Portal) UntagConnection(connectionId uint, tag string) {
	tagC := C.CString(tag)
	defer C.free(unsafe.Pointer(tagC))

	C.frida_portal_service_untag(p.portal, C.guint(connectionId), tagC)
}

func (p *Portal) On(sigName string, fn interface{}) {
	connectClosure(unsafe.Pointer(p.portal), sigName, fn)
}
