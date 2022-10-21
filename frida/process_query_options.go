package frida

//#include <frida-core.h>
import "C"

type ProcessQueryOptions struct {
	fpqo *C.FridaProcessQueryOptions
}

/*
func NewFridaProcessQueryOptions() *FridaProcessQueryOptions {
	opts := C.frida_application_query_options_new()
	return &FridaProcessQueryOptions{opts}
}
*/
