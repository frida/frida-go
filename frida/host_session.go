package frida

//#include <frida-core.h>
import "C"

type HostSession struct {
	hs *C.FridaHostSession
}

