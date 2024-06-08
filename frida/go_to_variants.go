package frida

/*
#include <frida-core.h>

static void add_key_val_to_builder(GVariantBuilder *builder, char * key, GVariant *variant)
{
	g_variant_builder_add(builder, "{sv}", key, variant);
}
*/
import "C"
import (
	"fmt"
	"reflect"
)

// goToGVariant converts go types to GVariant representation
func goToGVariant(data any) *C.GVariant {
	return parse(reflect.ValueOf(data))
}

func parse(v reflect.Value) *C.GVariant {
	for v.Kind() == reflect.Ptr || v.Kind() == reflect.Interface {
		v = v.Elem()
	}
	switch v.Kind() {
	case reflect.Array, reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			parse(v.Index(i))
		}
		return C.g_variant_new_string(C.CString("array"))
	case reflect.Map:
		var builder C.GVariantBuilder
		C.g_variant_builder_init(&builder, C.G_VARIANT_TYPE_VARDICT)
		for _, k := range v.MapKeys() {
			val := parse(v.MapIndex(k))
			C.add_key_val_to_builder(&builder, C.CString(k.String()), val)
		}
		variant := C.g_variant_builder_end(&builder)
		return variant
	case reflect.String:
		return C.g_variant_new_string(C.CString(v.String()))
	case reflect.Bool:
		if v.Interface().(bool) {
			return C.g_variant_new_boolean(C.gboolean(1))
		} else {
			return C.g_variant_new_boolean(C.gboolean(0))
		}
	default:
		msg := fmt.Sprintf("type \"%s\" not implemented", v.Kind().String())
		panic(msg)
	}
}
