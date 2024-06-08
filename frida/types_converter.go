package frida

/*
#include <frida-core.h>
#include <stdlib.h>

static char ** new_char_array(int size)
{
	return malloc(sizeof(char*) * size);
}

static void add_to_arr(char **arr, char *s, int n)
{
	arr[n] = s;
}

static char * get_char_elem(char **arr, int n)
{
	return arr[n];
}

static guint8 * new_guint8_array(int size)
{
	return malloc(sizeof(guint8) * size);
}

static void att_to_guint8_array(guint8 * arr, guint8 elem, int n)
{
	arr[n] = elem;
}
*/
import "C"

func getCharArrayElement(arr **C.char, n int) *C.char {
	elem := C.get_char_elem(arr, C.int(n))
	return elem
}

func stringSliceToCharArr(ss []string) (**C.char, C.int) {
	arr := C.new_char_array(C.int(len(ss)))

	for i, s := range ss {
		C.add_to_arr(arr, C.CString(s), C.int(i))
	}

	return arr, C.int(len(ss))
}

func goBytesToGBytes(bts []byte) *C.GBytes {
	arr := C.new_guint8_array(C.int(len(bts)))

	for i, bt := range bts {
		C.att_to_guint8_array(arr, C.guint8(bt), C.int(i))
	}

	gBytes := C.g_bytes_new((C.gconstpointer)(arr), C.gsize(len(bts)))
	return gBytes
}

func cArrayToStringSlice(arr **C.char, length C.int) []string {
	s := make([]string, int(length))

	for i := 0; i < int(length); i++ {
		elem := C.get_char_elem(arr, C.int(i))
		s[i] = C.GoString(elem)
	}

	return s
}
