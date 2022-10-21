package frida

/*#include <frida-core.h>
#include <stdlib.h>
#include <glib.h>
*/
import "C"
import "unsafe"

/*
FridaRemoteDeviceOptions * frida_remote_device_options_new (void);

GTlsCertificate * frida_remote_device_options_get_certificate (FridaRemoteDeviceOptions * self);
const gchar * frida_remote_device_options_get_origin (FridaRemoteDeviceOptions * self);
const gchar * frida_remote_device_options_get_token (FridaRemoteDeviceOptions * self);
gint frida_remote_device_options_get_keepalive_interval (FridaRemoteDeviceOptions * self);

void frida_remote_device_options_set_certificate (FridaRemoteDeviceOptions * self, GTlsCertificate * value);
void frida_remote_device_options_set_origin (FridaRemoteDeviceOptions * self, const gchar * value);
void frida_remote_device_options_set_token (FridaRemoteDeviceOptions * self, const gchar * value);
void frida_remote_device_options_set_keepalive_interval (FridaRemoteDeviceOptions * self, gint value);
*/

type RemoteDeviceOptions struct {
	opts *C.FridaRemoteDeviceOptions
}

func NewRemoteDeviceOptions() *RemoteDeviceOptions {
	opts := C.frida_remote_device_options_new()

	return &RemoteDeviceOptions{
		opts: opts,
	}
}

func gTlsCertificateFromFile(pempath string) (*C.GTlsCertificate, error) {
	cert := C.CString(pempath)
	defer C.free(unsafe.Pointer(cert))

	var err *C.GError
	gtls := C.g_tls_certificate_new_from_file(cert, &err)
	if err != nil {
		return nil, &FridaError{err}
	}

	return gtls, nil
}

func (f *RemoteDeviceOptions) SetCertificate(pempath string) error {
	cert, err := gTlsCertificateFromFile(pempath)
	if err != nil {
		return err
	}

	C.frida_remote_device_options_set_certificate(f.opts, cert)
	return nil
}

func (f *RemoteDeviceOptions) SetOrigin(origin string) {
	originC := C.CString(origin)
	defer C.free(unsafe.Pointer(originC))

	C.frida_remote_device_options_set_origin(f.opts, originC)
}

func (f *RemoteDeviceOptions) SetToken(token string) {
	tokenC := C.CString(token)
	defer C.free(unsafe.Pointer(tokenC))

	C.frida_remote_device_options_set_token(f.opts, tokenC)
}

func (f *RemoteDeviceOptions) SetKeepAlive(interval int) {
	C.frida_remote_device_options_set_keepalive_interval(f.opts, C.gint(interval))
}
