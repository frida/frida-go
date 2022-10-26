package frida

//#include "authentication-service.h"
import "C"
import (
	"errors"
	"unsafe"
)

// AuthenticationFn is a callback function passed to the endpoint params.
// Function does authentication and in the case the user is authenticated,
// non-empty string is returned.
// If the user is not authenticated, empty string should be returned.
type AuthenticationFn func(string) string

// EParams represent config needed to setup endpoint parameters that are used to setup Portal.
// Types of authentication includes:
//	- no authentication (not providing Token nor AuthenticationCallback)
//	- static authentication (providing token)
//	- authentication using callback (providing AuthenticationCallback)
//
// If the Token and AuthenticationCallback are passed, static authentication will be used (token based)
type EParams struct {
	Address                string
	Port                   uint16
	Certificate            string
	Origin                 string
	Token                  string
	AuthenticationCallback AuthenticationFn
	AssetRoot              string
}

// EndpointParameters represent internal FridaEndpointParameters
type EndpointParameters struct {
	params *C.FridaEndpointParameters
}

//export authenticate
func authenticate(cb unsafe.Pointer, token *C.char) *C.char {
	fn := (*func(string) string)(cb)
	ret := (*fn)(C.GoString(token))
	if ret == "" {
		return nil
	}
	return C.CString(ret)
}

// NewEndpointParameters returns *EndpointParameters needed to setup Portal by using
// provided EParams object
func NewEndpointParameters(params *EParams) (*EndpointParameters, error) {
	if params.Address == "" {
		return nil, errors.New("You need to provide address")
	}

	addrC := C.CString(params.Address)
	defer C.free(unsafe.Pointer(addrC))

	var tknC *C.char = nil
	var originC *C.char = nil
	var auth_service *C.FridaAuthenticationService = nil

	if params.Token != "" {
		tknC = C.CString(params.Token)
		defer C.free(unsafe.Pointer(tknC))

		auth_service = (*C.FridaAuthenticationService)(C.frida_static_authentication_service_new(tknC))
	} else if params.AuthenticationCallback != nil {
		auth_service = (*C.FridaAuthenticationService)(C.frida_go_authentication_service_new(unsafe.Pointer(&params.AuthenticationCallback)))
	}

	if params.Origin != "" {
		originC = C.CString(params.Origin)
		defer C.free(unsafe.Pointer(originC))
	}

	cert, _ := gTlsCertificateFromFile(params.Certificate)
	_ = cert
	ret := C.frida_endpoint_parameters_new(
		addrC,
		C.guint16(params.Port),
		nil,
		originC,
		auth_service,
		nil,
	)

	return &EndpointParameters{ret}, nil
}
