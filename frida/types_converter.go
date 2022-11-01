package frida

/*
#include <glib.h>
#include <glib-object.h>
#include <frida-core.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>

static char * get_gvalue_gtype(GValue * val) {
	return (char*)(G_VALUE_TYPE_NAME(val));
}

static char * get_ip_str(const struct sockaddr *sa, size_t maxlen)
{
	char * dest = malloc(sizeof(char) * maxlen);
    switch(sa->sa_family) {
        case AF_INET:
            inet_ntop(AF_INET, &(((struct sockaddr_in *)sa)->sin_addr),
                    dest, maxlen);
            break;

        case AF_INET6:
            inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)sa)->sin6_addr),
                    dest, maxlen);
            break;

        default:
            strncpy(dest, "Unknown AF", maxlen);
            return NULL;
    }

    return dest;
}

static int get_in_port(struct sockaddr *sa)
{
	in_port_t port;
    if (sa->sa_family == AF_INET)
        port = (((struct sockaddr_in*)sa)->sin_port);

    port = (((struct sockaddr_in6*)sa)->sin6_port);

	return (int)port;
}

static struct sockaddr * new_addr() {
	struct sockaddr * addr = malloc(sizeof(struct sockaddr));
	return addr;
}


static char ** new_char_array(int size) {
	return malloc(sizeof(char*) * size);
}
static void add_to_arr(char **arr, char *s, int n) {
	arr[n] = s;
}
static char * get_char_elem(char **arr, int n) {
	return arr[n];
}
static guint8 * new_guint8_array(int size) {
	return malloc(sizeof(guint8) * size);
}
static void att_to_guint8_array(guint8 * arr, guint8 elem, int n) {
	arr[n] = elem;
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
	fridaApplication         GTypeName = "FridaApplication"
	guint                    GTypeName = "guint"
	gint                     GTypeName = "gint"
	gFileMonitorEvent        GTypeName = "GFileMonitorEvent"
	gSocketAddress           GTypeName = "GSocketAddress"
)

type marshallerFunc func(val *C.GValue) interface{}

var GTypeString = map[GTypeName]marshallerFunc{
	gchararray:               getString,
	gBytes:                   getGBytesV,
	fridaCrash:               getFridaCrash,
	fridaSessionDetachReason: getFridaSessionDetachReason,
	fridaChild:               getFridaChild,
	fridaDevice:              getFridaDevice,
	fridaApplication:         getFridaApplication,
	guint:                    getInt,
	gint:                     getInt,
	gFileMonitorEvent:        getFm,
	gSocketAddress:           getGSocketAddress,
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

func getGSocketAddress(val *C.GValue) interface{} {
	obj := (*C.GSocketAddress)(C.g_value_get_object(val))
	sz := C.g_socket_address_get_native_size(obj)
	dest := C.new_addr()
	var err *C.GError
	C.g_socket_address_to_native(obj, (C.gpointer)(dest), C.gsize(sz), &err)
	if err != nil {
		panic(err)
	}

	s := C.get_ip_str(dest, C.size_t(sz))
	port := C.get_in_port(dest)

	return &Address{
		Addr: C.GoString(s),
		Port: uint16(port),
	}
}

func getFridaApplication(val *C.GValue) interface{} {
	app := (*C.FridaApplication)(C.g_value_get_object(val))

	return &Application{
		application: app,
	}
}

func getGoValueFromGValue(val *C.GValue) interface{} {
	gt := C.get_gvalue_gtype(val)

	f, ok := GTypeString[GTypeName(C.GoString(gt))]
	if !ok {
		return struct{}{}
	}

	return f(val)
}

func getCharArrayElement(arr **C.char, n int) *C.char {
	elem := C.get_char_elem(arr, C.int(n))
	return elem
}

func cArrayToStringSlice(arr **C.char, length C.int) []string {
	s := []string{}

	for i := 0; i < int(length); i++ {
		elem := C.get_char_elem(arr, C.int(i))
		s = append(s, C.GoString(elem))
	}

	return s
}

func stringSliceToCharArr(ss []string) (**C.char, C.int) {
	arr := C.new_char_array(C.int(len(ss)))

	for i, s := range ss {
		C.add_to_arr(arr, C.CString(s), C.int(i))
	}

	return arr, C.int(len(ss))
}

func uint8ArrayFromByteSlice(bts []byte) (*C.guint8, C.int) {
	arr := C.new_guint8_array(C.int(len(bts)))

	for i, bt := range bts {
		C.att_to_guint8_array(arr, C.guint8(bt), C.int(i))
	}

	return arr, C.int(len(bts))
}

func goBytesToGBytes(bts []byte) *C.GBytes {
	arr := C.new_guint8_array(C.int(len(bts)))

	for i, bt := range bts {
		C.att_to_guint8_array(arr, C.guint8(bt), C.int(i))
	}

	gBytes := C.g_bytes_new((C.gconstpointer)(arr), C.gsize(len(bts)))
	return gBytes
}
