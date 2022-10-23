package frida

//#include <frida-core.h>
import "C"

type PortalMembership struct {
	mem *C.FridaPortalMembership
}

func (p *PortalMembership) GetID() uint {
	return uint(C.frida_portal_membership_get_id(p.mem))
}

func (p *PortalMembership) Terminate() error {
	var err *C.GError
	C.frida_portal_membership_terminate_sync(p.mem, nil, &err)
	if err != nil {
		return &FridaError{err}
	}
	return nil
}
