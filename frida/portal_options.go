package frida

//#include <frida-core.h>
import "C"
import "unsafe"

type PortalOptions struct {
	opts *C.FridaPortalOptions
}

func NewPortalOptions() *PortalOptions {
	opts := C.frida_portal_options_new()
	return &PortalOptions{
		opts: opts,
	}
}

func (f *PortalOptions) SetCertificate(pempath string) error {
	cert, err := gTlsCertificateFromFile(pempath)
	if err != nil {
		return err
	}

	C.frida_portal_options_set_certificate(f.opts, cert)
	return nil
}

func (f *PortalOptions) SetToken(token string) {
	tokenC := C.CString(token)
	defer C.free(unsafe.Pointer(tokenC))

	C.frida_portal_options_set_token(f.opts, tokenC)
}
