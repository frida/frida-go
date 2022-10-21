package frida

//#include <frida-core.h>
import "C"

import "unsafe"

// FridaDeviceManager is the main structure which holds on devices available to Frida
type DeviceManager struct {
	manager *C.FridaDeviceManager
}

// NewManager will return pointer to FridaDeviceManager and an error in case of failure.
// NewManager will also populate Devices inside the same object.
func NewManager() *DeviceManager {
	manager := C.frida_device_manager_new()

	mgr := &DeviceManager{manager}

	return mgr
}

// Close() method will close FridaDeviceManager by calling frida_device_manager_close_sync
func (f DeviceManager) Close() {
	C.frida_device_manager_close_sync(f.manager, nil, nil)
}

func (f DeviceManager) On(sigName string, fn interface{}) {
	connectClosure(unsafe.Pointer(f.manager), sigName, fn)
}

// EnumerateDevices will return all devices
func (d DeviceManager) EnumerateDevices() ([]*Device, error) {
	var err *C.GError
	deviceList := C.frida_device_manager_enumerate_devices_sync(d.manager, nil, &err)
	if err != nil {
		return nil, &FridaError{err}
	}

	var devices []*Device
	numDevices := int(C.frida_device_list_size(deviceList))

	for i := 0; i < numDevices; i++ {
		device := C.frida_device_list_get(deviceList, C.gint(i))
		devices = append(devices, &Device{device: device})
	}

	return devices, nil
}

// GetLocalDevice returns the device from Devices map with type FRIDA_DEVICE_TYPE_LOCAL.
func (d DeviceManager) GetLocalDevice() (*Device, error) {
	return d.GetDeviceByType(FRIDA_DEVICE_TYPE_LOCAL)
}

// GetUSBDevice returns the device from Devices map with type FRIDA_DEVICE_TYPE_USB.
func (d DeviceManager) GetUSBDevice() (*Device, error) {
	return d.GetDeviceByType(FRIDA_DEVICE_TYPE_USB)
}

// GetRemoteDevice returns the device from Devices map with type FRIDA_DEVICE_TYPE_REMOTE.
func (d DeviceManager) GetRemoteDevice() (*Device, error) {
	return d.GetDeviceByType(FRIDA_DEVICE_TYPE_REMOTE)
}

// GetDevice will return device with id passed
func (d DeviceManager) GetDeviceByID(id string) (*Device, error) {
	var err *C.GError
	idS := C.CString(id)
	defer objectFree(unsafe.Pointer(idS))
	device := C.frida_device_manager_get_device_by_id_sync(d.manager, idS, 1, nil, &err)
	if err != nil {
		return nil, &FridaError{err}
	}
	return &Device{device: device}, nil
}

func (d DeviceManager) GetDeviceByType(devType DeviceType) (*Device, error) {
	var err *C.GError
	device := C.frida_device_manager_get_device_by_type_sync(d.manager, C.FridaDeviceType(devType), 1, nil, &err)
	if err != nil {
		return nil, &FridaError{err}
	}
	return &Device{device: device}, nil
}

// FridaDeviceById function will try to find the device by id specified
func (d DeviceManager) FindDeviceByID(id string, timeout int) (*Device, error) {
	devId := C.CString(id)
	defer C.free(unsafe.Pointer(devId))

	if timeout == 0 {
		timeout = 1
	}

	var err *C.GError
	device := C.frida_device_manager_find_device_by_id_sync(d.manager, devId, C.gint(timeout), nil, &err)
	if err != nil {
		return nil, &FridaError{err}
	}

	return &Device{device: device}, nil
}

// FridaDevice * frida_device_manager_find_device_by_type_sync (FridaDeviceManager * self,
// FridaDeviceType type, gint timeout, GCancellable * cancellable, GError ** error);
func (d DeviceManager) FindDeviceByType(devType DeviceType, timeout int) (*Device, error) {
	if timeout == 0 {
		timeout = 1
	}

	var err *C.GError
	device := C.frida_device_manager_find_device_by_type_sync(d.manager,
		C.FridaDeviceType(devType),
		C.gint(timeout),
		nil,
		&err)
	if err != nil {
		return nil, &FridaError{err}
	}

	return &Device{device: device}, nil
}

func (d DeviceManager) AddRemoteDevice(address string, remoteOpts *RemoteDeviceOptions) (*Device, error) {
	addressC := C.CString(address)
	defer C.free(unsafe.Pointer(addressC))

	var err *C.GError
	device := C.frida_device_manager_add_remote_device_sync(d.manager, addressC, remoteOpts.opts, nil, &err)
	if err != nil {
		return nil, &FridaError{err}
	}

	return &Device{device: device}, nil
}
