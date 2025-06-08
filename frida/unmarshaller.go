package frida

/*
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "Ws2_32.lib")
	typedef unsigned short in_port_t;
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
#endif

#include <frida-core.h>

static char * get_gvalue_gtype(GValue * val) {
	return (char*)(G_VALUE_TYPE_NAME(val));
}

static int get_in_port(struct sockaddr *sa)
{
	in_port_t port;
    if (sa->sa_family == AF_INET)
        port = (((struct sockaddr_in*)sa)->sin_port);

    port = (((struct sockaddr_in6*)sa)->sin6_port);

	return (int)port;
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

static struct sockaddr * new_sockaddr() {
	struct sockaddr * addr = malloc(sizeof(struct sockaddr));
	return addr;
}
*/
import "C"
import (
	"fmt"
	"unsafe"
)

type gTypeName string

const (
	gchararray               gTypeName = "gchararray"
	gBytes                   gTypeName = "GBytes"
	fridaCrash               gTypeName = "FridaCrash"
	fridaSessionDetachReason gTypeName = "FridaSessionDetachReason"
	fridaChild               gTypeName = "FridaChild"
	fridaDevice              gTypeName = "FridaDevice"
	fridaApplication         gTypeName = "FridaApplication"
	guint                    gTypeName = "guint"
	gint                     gTypeName = "gint"
	gFileMonitorEvent        gTypeName = "GFileMonitorEvent"
	gSocketAddress           gTypeName = "GSocketAddress"
	gVariant                 gTypeName = "GVariant"
)

type unmarshallerFunc func(val *C.GValue) any

var gTypeString = map[gTypeName]unmarshallerFunc{
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
	gVariant:                 getGVariant,
}

// GValueToGo is the function that is called upon unmarshalling glib values
// into go corresponding ones.
func GValueToGo(val *C.GValue) any {
	gt := C.get_gvalue_gtype(val)
	cgt := C.GoString(gt)

	f, ok := gTypeString[gTypeName(cgt)]
	if !ok {
		return fmt.Sprintf("%s type is not implemented, please file an issue", cgt)
	}

	return f(val)
}

func getString(val *C.GValue) any {
	cc := C.g_value_get_string(val)
	return C.GoString(cc)
}

func getGBytesV(val *C.GValue) any {
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

func getFridaCrash(val *C.GValue) any {
	crash := (*C.FridaCrash)(C.g_value_get_object(val))

	return &Crash{
		crash: crash,
	}
}

func getFridaSessionDetachReason(val *C.GValue) any {
	reason := C.g_value_get_int(val)
	return SessionDetachReason(int(reason))
}

func getFridaChild(val *C.GValue) any {
	child := (*C.FridaChild)(C.g_value_get_object(val))

	return &Child{
		child: child,
	}
}

func getFridaDevice(val *C.GValue) any {
	dev := (*C.FridaDevice)(C.g_value_get_object(val))

	return &Device{
		device: dev,
	}
}

func getFridaApplication(val *C.GValue) any {
	app := (*C.FridaApplication)(C.g_value_get_object(val))

	return &Application{
		application: app,
	}
}

func getInt(val *C.GValue) any {
	v := C.g_value_get_int(val)
	return int(v)
}

func getFm(val *C.GValue) any {
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

func getGSocketAddress(val *C.GValue) any {
	obj := (*C.GSocketAddress)(C.g_value_get_object(val))
	sz := C.g_socket_address_get_native_size(obj)
	dest := C.new_sockaddr()
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

func getGVariant(val *C.GValue) any {
	v := C.g_value_get_variant(val)
	return gVariantToGo(v)
}
