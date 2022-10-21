package frida

/*
#include <frida-core.h>
#include <glib.h>
#include <stdlib.h>
#include <stdio.h>

extern void getSVArray(gchar*,GVariant*,char*);
extern void getASVArray(gchar*,GVariant*,char*);

static void iter_array(GVariant *var, char *aData) {
	GVariantIter iter;
	GVariant *value;
	gchar *key;

	g_variant_iter_init (&iter, var);
	while (g_variant_iter_loop (&iter, "{sv}", &key, &value))
	{
			getSVArray(key, value, aData);
	}
}

static void iter_double_arr(GVariant *var, char *mData) {
	GVariantIter iter1;
	GVariantIter *iter2;

	g_variant_iter_init(&iter1, var);
	while (g_variant_iter_loop (&iter1, "a{sv}", &iter2)) {
		GVariant *val;
		gchar *key;

		while (g_variant_iter_loop(iter2, "{sv}", &key, &val)) {
			gchar * tp;
			tp = (char*)g_variant_get_type_string(val);
			getASVArray(key, val, mData);
		}
	}
}

static size_t getElemsSize() {
	return sizeof(guint8);
}

*/
import "C"
import (
	"unsafe"
)

type arrData struct {
	mapper map[string]interface{}
}

type multiData struct {
	mapper map[string]interface{}
}

//export getSVArray
func getSVArray(key *C.gchar, variant *C.GVariant, aData *C.char) {
	k := C.GoString((*C.char)(key))
	v := stringFromVariant(variant)
	arrayData := (*arrData)(unsafe.Pointer(aData))
	arrayData.mapper[k] = v
}

//export getASVArray
func getASVArray(key *C.gchar, variant *C.GVariant, mData *C.char) {
	keyGo := C.GoString(key)
	vType := getVariantStringFormat(variant)
	multData := (*multiData)(unsafe.Pointer(mData))
	if vType == "s" {
		multData.mapper[keyGo] = stringFromVariant(variant)
	} else {
		multData.mapper[keyGo] = bytesFromVariant(variant)
	}
}

func getVariantStringFormat(variant *C.GVariant) string {
	variantString := ""
	if variant != nil {
		variantType := C.g_variant_get_type_string(variant)
		variantString = C.GoString((*C.char)(variantType))
	}
	return variantString
}

func bytesFromVariant(variant *C.GVariant) []byte {
	var res *C.char
	sz := C.g_variant_get_size(variant)
	res = (*C.char)((C.g_variant_get_data(variant)))
	bts := C.GoBytes(unsafe.Pointer(res), C.int(sz))
	return bts
}

// stringFromVariant extracts bool ("b") from GVariant
func stringFromVariant(variant *C.GVariant) string {
	var sz C.gsize
	return C.GoString(C.g_variant_get_string(variant, &sz))
}

// stringFromVariant extracts string ("s") from GVariant
func boolFromVariant(variant *C.GVariant) bool {
	val := C.g_variant_get_boolean(variant)
	if int(val) == 0 {
		return false
	}
	return true
}

func int64FromVariant(variant *C.GVariant) int64 {
	val := C.g_variant_get_int64(variant)
	return int64(val)
}

func gPointerToGo(ptr C.gpointer) interface{} {
	variant := (*C.GVariant)(ptr)
	variantType := getVariantStringFormat(variant)

	switch variantType {
	case "s":
		return stringFromVariant(variant)
	case "b":
		return boolFromVariant(variant)
	case "x":
		return int64FromVariant(variant)
	case "a{sv}":
		mp := make(map[string]interface{})
		aData := arrData{
			mapper: mp,
		}
		C.iter_array(variant, (*C.char)(unsafe.Pointer(&aData)))
		return aData.mapper
	case "aa{sv}":
		mp := make(map[string]interface{})
		mData := multiData{
			mapper: mp,
		}
		C.iter_double_arr(variant, (*C.char)(unsafe.Pointer(&mData)))
		return mData.mapper
	default:
		return variantType
	}
}

func gVariantToGo(variant *C.GVariant) interface{} {
	return gPointerToGo((C.gpointer)(variant))
}
