package frida

import "C"

/*#include <frida-core.h>
#include <stdio.h>

static GVariant * new_variant_from_c_string(const char * val, FridaService * svc)
{
	GVariantBuilder builder;

	g_variant_builder_init (&builder, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_add(&builder, "{sv}", "method", g_variant_new_string("takeScreenshot"));
	GVariant * variant = g_variant_builder_end(&builder);

	return variant;
}

*/
import "C"

type ServiceInt interface {
}

// Service represents Service from frida-core
type Service struct {
	service *C.FridaService
}

func (s *Service) Request(req any) (any, error) {
	variant := goToGVariant(req)

	var gerr *C.GError
	resp := C.frida_service_request_sync(s.service, variant, nil, &gerr)
	if gerr != nil {
		return nil, &FError{gerr}
	}

	return gVariantToGo(resp), nil
}
