package frida

/*
#include <frida-core.h>

static void add_key_val_to_builder(GVariantBuilder *builder, char *key, GVariant *variant)
{
	g_variant_builder_add(builder, "{sv}", key, variant);
}

static void add_val_to_builder(GVariantBuilder *builder, GVariant *variant)
{
	g_variant_builder_add(builder, "v", variant);
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
		var builder C.GVariantBuilder
		C.g_variant_builder_init(&builder, C.G_VARIANT_TYPE_ARRAY)
		for i := 0; i < v.Len(); i++ {
			val := parse(v.Index(i))
			C.add_val_to_builder(&builder, val)
		}
		variant := C.g_variant_builder_end(&builder)
		return variant
	case reflect.Map:
		var builder C.GVariantBuilder
		C.g_variant_builder_init(&builder, C.G_VARIANT_TYPE_VARDICT)
		for _, k := range v.MapKeys() {
			val := parse(v.MapIndex(k))
			C.add_key_val_to_builder(&builder, C.CString(k.String()), val)
		}
		variant := C.g_variant_builder_end(&builder)
		return variant
	case reflect.Bool:
		if v.Interface().(bool) {
			return C.g_variant_new_boolean(C.gboolean(1))
		} else {
			return C.g_variant_new_boolean(C.gboolean(0))
		}
	case reflect.String:
		return C.g_variant_new_string(C.CString(v.String()))
	case reflect.Int16:
		return C.g_variant_new_int16(C.gint16(v.Interface().(int16)))
	case reflect.Uint16:
		return C.g_variant_new_uint16(C.guint16(v.Interface().(uint16)))
	case reflect.Int:
		return C.g_variant_new_int32(C.gint32(v.Interface().(int)))
	case reflect.Int32:
		return C.g_variant_new_int32(C.gint32(v.Interface().(int32)))
	case reflect.Uint32:
		return C.g_variant_new_uint32(C.guint32(v.Interface().(uint32)))
	case reflect.Int64:
		return C.g_variant_new_int64(C.gint64(v.Interface().(int64)))
	case reflect.Uint64:
		return C.g_variant_new_int64(C.gint64(v.Interface().(int64)))
	default:
		msg := fmt.Sprintf("type \"%s\" not implemented, please file an issue on github", v.Kind().String())
		panic(msg)
	}
	return nil
}
