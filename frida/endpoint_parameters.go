package frida

//#include <frida-core.h>
import "C"
import "unsafe"

/*FridaEndpointParameters * frida_endpoint_parameters_new
(const gchar * address,
	guint16 port,
	GTlsCertificate * certificate,
	const gchar * origin,
	FridaAuthenticationService * auth_service,
	GFile * asset_root);

*/

type EParams struct {
	Address     string
	Port        uint16
	Certificate string
	Origin      string
	Token       string
	AssetRoot   string
}

type EndpointParameters struct {
	params *C.FridaEndpointParameters
}

func NewEndpointParameters(params *EParams) (*EndpointParameters, error) {
	tkn := C.CString(params.Token)
	defer C.free(unsafe.Pointer(tkn))

	addr := C.CString(params.Address)
	defer C.free(unsafe.Pointer(addr))

	origin := C.CString(params.Origin)
	defer C.free(unsafe.Pointer(origin))

	cert, _ := gTlsCertificateFromFile(params.Certificate)
	_ = cert

	auth := C.frida_static_authentication_service_new(tkn)

	ret := C.frida_endpoint_parameters_new(
		addr,
		C.guint16(params.Port),
		nil,
		nil,
		(*C.FridaAuthenticationService)(auth),
		nil,
	)

	return &EndpointParameters{ret}, nil
}
