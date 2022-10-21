package frida

/*
#include <glib.h>
#include <glib-object.h>
#include <frida-core.h>
#include <stdio.h>

static char * get_gvalue_gtype(GValue * val) {
	return (char*)(G_VALUE_TYPE_NAME(val));
}
*/
import "C"
import (
	"unsafe"
)

type GTypeName string

const (
	gchararray               GTypeName = "gchararray"
	gBytes                   GTypeName = "GBytes"
	fridaCrash               GTypeName = "FridaCrash"
	fridaSessionDetachReason GTypeName = "FridaSessionDetachReason"
	fridaChild               GTypeName = "FridaChild"
	fridaDevice              GTypeName = "FridaDevice"
	guint                    GTypeName = "guint"
	gint                     GTypeName = "gint"
	gFileMonitorEvent        GTypeName = "GFileMonitorEvent"
)

type marshallerFunc func(val *C.GValue) interface{}

var GTypeString = map[GTypeName]marshallerFunc{
	gchararray:               getString,
	gBytes:                   getGBytesV,
	fridaCrash:               getFridaCrash,
	fridaSessionDetachReason: getFridaSessionDetachReason,
	fridaChild:               getFridaChild,
	fridaDevice:              getFridaDevice,
	guint:                    getInt,
	gint:                     getInt,
	gFileMonitorEvent:        getFm,
}

func getString(val *C.GValue) interface{} {
	cc := C.g_value_get_string(val)
	return C.GoString(cc)
}

func getGBytesV(val *C.GValue) interface{} {
	if val != nil {
		obj := (*C.GBytes)(C.g_value_get_object(val))
		return getGBytes(obj)
	}
	return []byte{}
}

func getGBytes(obj *C.GBytes) []byte {
	if obj != nil {
		bytesC := (*C.guint8)(C.g_bytes_get_data(obj, nil))
		sz := C.g_bytes_get_size(obj)

		return C.GoBytes(unsafe.Pointer(bytesC), C.int(sz))
	}
	return []byte{}
}

func getFridaCrash(val *C.GValue) interface{} {
	crash := (*C.FridaCrash)(C.g_value_get_object(val))

	return &Crash{
		crash: crash,
	}
}

func getFridaSessionDetachReason(val *C.GValue) interface{} {
	reason := C.g_value_get_int(val)
	return SessionDetachReason(int(reason))
}

func getFridaChild(val *C.GValue) interface{} {
	child := (*C.FridaChild)(C.g_value_get_object(val))

	return &Child{
		child: child,
	}
}

func getFridaDevice(val *C.GValue) interface{} {
	dev := (*C.FridaDevice)(C.g_value_get_object(val))

	return &Device{
		device: dev,
	}
}

func getInt(val *C.GValue) interface{} {
	v := C.g_value_get_int(val)
	return int(v)
}

func getFm(val *C.GValue) interface{} {
	v := C.int(C.g_value_get_int(val))

	/*
		typedef enum {
		  G_FILE_MONITOR_EVENT_CHANGED,
		  G_FILE_MONITOR_EVENT_CHANGES_DONE_HINT,
		  G_FILE_MONITOR_EVENT_DELETED,
		  G_FILE_MONITOR_EVENT_CREATED,
		  G_FILE_MONITOR_EVENT_ATTRIBUTE_CHANGED,
		  G_FILE_MONITOR_EVENT_PRE_UNMOUNT,
		  G_FILE_MONITOR_EVENT_UNMOUNTED,
		  G_FILE_MONITOR_EVENT_MOVED
		} GFileMonitorEvent;
	*/
	vals := map[int]string{
		0: "changed",
		1: "changes-done-hint",
		2: "deleted",
		3: "created",
		4: "attribute-changed",
		5: "pre-mount",
		6: "unmounted",
		7: "moved",
	}

	return vals[int(v)]
}

func goValueFromGValue(val *C.GValue) interface{} {
	return nil
}

func getGoValueFromGValue(val *C.GValue) interface{} {
	gt := C.get_gvalue_gtype(val)

	f, ok := GTypeString[GTypeName(C.GoString(gt))]
	if !ok {
		return struct{}{}
	}

	return f(val)
}
