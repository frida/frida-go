package frida

//#include <glib.h>
import "C"
import "unsafe"

func gHashTableToMap(ht *C.GHashTable) map[string]interface{} {
	iter := C.GHashTableIter{}
	var key C.gpointer
	var val C.gpointer

	data := make(map[string]interface{})

	C.g_hash_table_iter_init(&iter, ht)

	hSize := int(C.g_hash_table_size(ht))

	if hSize >= 1 {
		nx := 1
		for nx == 1 {
			nx = int(C.g_hash_table_iter_next(&iter, &key, &val))

			keyGo := C.GoString((*C.char)(unsafe.Pointer(key)))
			valGo := gPointerToGo(val)

			data[keyGo] = valGo
		}
	}

	return data
}
