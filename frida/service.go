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

func (s *Service) Activate() error {
	var err *C.GError
	C.frida_service_activate_sync(s.service, nil, &err)
	if err != nil {
		return &FError{err}
	}
	return nil
}

func (s *Service) Cancel() error {
	var err *C.GError
	C.frida_service_cancel_sync(s.service, nil, &err)
	if err != nil {
		return &FError{err}
	}
	return nil
}

func (s *Service) IsClosed() bool {
	val := C.frida_service_is_closed(s.service)
	return int(val) != 0
}
