package frida

/*
#include <frida-core.h>

extern void getSVArray(gchar*,GVariant*,char*);
extern void getASVArray(gchar*,GVariant*,char*);
extern void populateSliceLoop(GVariant*,char*);

static void loop_simple_array(GVariant ** variant, char * fmt, char * slc)
{
	GVariantIter iter;
	GVariant * v;

	g_variant_iter_init(&iter, *variant);
	while(g_variant_iter_loop(&iter, fmt, &v))
		populateSliceLoop(v, slc);
}

static void iter_array_of_dicts(GVariant *var, char *data)
{
	GVariantIter iter;
	GVariant *value;
	gchar *key;

	g_variant_iter_init (&iter, var);
	while (g_variant_iter_loop (&iter, "{sv}", &key, &value))
	{
			getSVArray(key, value, data);
	}
}

static void iter_double_array_of_dicts(GVariant *var, char *data)
{
	GVariantIter iter1;
	GVariantIter *iter2;

	g_variant_iter_init(&iter1, var);
	while (g_variant_iter_loop (&iter1, "a{sv}", &iter2)) {
		GVariant *val;
		gchar *key;

		while (g_variant_iter_loop(iter2, "{sv}", &key, &val)) {
			gchar * tp;
			tp = (char*)g_variant_get_type_string(val);
			getASVArray(key, val, data);
		}
	}
}

static char* read_byte_array(GVariant *variant, int * n_elements)
{
	guint8 * array = NULL;

	array = g_variant_get_fixed_array (variant,
									   (gsize)n_elements,
									   sizeof(guint8));
	return (char*)array;
}
*/
import "C"
import (
	"fmt"
	"unsafe"
)

type variantSlice struct {
	s []*C.GVariant
}

type genericMap struct {
	m map[string]any
}

//export getSVArray
func getSVArray(key *C.gchar, variant *C.GVariant, aData *C.char) {
	k := C.GoString((*C.char)(key))
	v := gVariantToGo(variant)
	mp := (*genericMap)(unsafe.Pointer(aData))
	mp.m[k] = v
}

//export getASVArray
func getASVArray(key *C.gchar, variant *C.GVariant, mData *C.char) {
	keyGo := C.GoString(key)
	mp := (*genericMap)(unsafe.Pointer(mData))
	mp.m[keyGo] = gVariantToGo(variant)
}

//export populateSliceLoop
func populateSliceLoop(variant *C.GVariant, slc *C.char) {
	s := (*variantSlice)(unsafe.Pointer(slc))
	s.s = append(s.s, variant)
}

// gVariantToGo converts GVariant to corresponding go type
func gVariantToGo(variant *C.GVariant) any {
	variantType := getVariantStringFormat(variant)

	switch variantType {
	case "s":
		return stringFromVariant(variant)
	case "b":
		return boolFromVariant(variant)
	case "x":
		return int64FromVariant(variant)
	case "v":
		v := C.g_variant_get_variant(variant)
		return gVariantToGo(v)
	case "a{sv}":
		mp := make(map[string]any)
		gm := genericMap{
			m: mp,
		}
		C.iter_array_of_dicts(variant, (*C.char)(unsafe.Pointer(&gm)))
		return gm.m
	case "av":
		s := variantSlice{}
		C.loop_simple_array(&variant, C.CString("v"), (*C.char)(unsafe.Pointer(&s)))
		arr := make([]any, len(s.s))
		for i, elem := range s.s {
			arr[i] = gVariantToGo(elem)
		}
		return arr
	case "aa{sv}":
		mp := make(map[string]any)
		gm := genericMap{
			m: mp,
		}
		C.iter_double_array_of_dicts(variant, (*C.char)(unsafe.Pointer(&gm)))
		return gm.m
	case "ay": // array of bytes
		var n_elements C.int
		cBytes := C.read_byte_array(variant, &n_elements)
		return C.GoBytes(unsafe.Pointer(cBytes), n_elements)
	default:
		return fmt.Sprintf("type \"%s\" not implemented", variantType)
	}
}

// getVariantStringFormat returns underlying variant type
func getVariantStringFormat(variant *C.GVariant) string {
	variantString := ""
	if variant != nil {
		variantType := C.g_variant_get_type_string(variant)
		variantString = C.GoString((*C.char)(variantType))
	}
	return variantString
}

// stringFromVariant extracts string from GVariant
func stringFromVariant(variant *C.GVariant) string {
	var sz C.gsize
	return C.GoString(C.g_variant_get_string(variant, &sz))
}

// stringFromVariant extracts string from GVariant
func boolFromVariant(variant *C.GVariant) bool {
	val := C.g_variant_get_boolean(variant)
	return int(val) != 0
}

// int64FromVariant extracts int64 from GVariant
func int64FromVariant(variant *C.GVariant) int64 {
	val := C.g_variant_get_int64(variant)
	return int64(val)
}

// gPointerToGo converts gpointer to corresponding go type
func gPointerToGo(ptr C.gpointer) any {
	return gVariantToGo((*C.GVariant)(ptr))
}

// gHashTableToMap converts GHashTable to go map
func gHashTableToMap(ht *C.GHashTable) map[string]any {
	iter := C.GHashTableIter{}
	var key C.gpointer
	var val C.gpointer

	C.g_hash_table_iter_init(&iter, ht)

	hSize := int(C.g_hash_table_size(ht))
	var data map[string]any

	if hSize >= 1 {
		data = make(map[string]any, hSize)
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
