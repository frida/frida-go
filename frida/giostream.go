package frida

//#include <gio/gio.h>
import "C"

type GIOStream struct {
	stream *C.GIOStream
}
