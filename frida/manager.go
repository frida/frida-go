package frida

//#include <frida-core.h>
import "C"

import "unsafe"

const (
	defaultDeviceTimeout = 10
)

// DeviceManager is the main structure which holds on devices available to Frida
// Single instance of the DeviceManager is created when you call frida.Attach() or frida.GetLocalDevice().
type DeviceManager struct {
	manager *C.FridaDeviceManager
}

// NewManager returns new frida device manager.
func NewDeviceManager() *DeviceManager {
	manager := C.frida_device_manager_new()
	mgr := &DeviceManager{manager}
	return mgr
}

// Close() method will close current manager.
func (f *DeviceManager) Close() error {
	var err *C.GError
	C.frida_device_manager_close_sync(f.manager, nil, &err)
	if err != nil {
		return &FridaError{err}
	}
	return nil
}

// On connects manager to specific signals. Once sigName is trigerred,
// fn callback will be called with parameters populated.
//
// Signals available are:
//	- "added" with callback as func(device *frida.Devica) {}
//	- "removed" with callback as func(device *frida.Device) {}
//	- "changed" with callback as func() {}
func (f *DeviceManager) On(sigName string, fn interface{}) {
	connectClosure(unsafe.Pointer(f.manager), sigName, fn)
}

// EnumerateDevices will return all connected devices and an error
func (d *DeviceManager) EnumerateDevices() ([]*Device, error) {
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

// GetLocalDevice returns the device with type DEVICE_TYPE_LOCAL.
func (d *DeviceManager) GetLocalDevice() (*Device, error) {
	return d.GetDeviceByType(DEVICE_TYPE_LOCAL)
}

// GetUSBDevice returns the device with type DEVICE_TYPE_USB.
func (d *DeviceManager) GetUSBDevice() (*Device, error) {
	return d.GetDeviceByType(DEVICE_TYPE_USB)
}

// GetRemoteDevice returns the device with type DEVICE_TYPE_REMOTE.
func (d *DeviceManager) GetRemoteDevice() (*Device, error) {
	return d.GetDeviceByType(DEVICE_TYPE_REMOTE)
}

// GetDevice will return device with id passed or an error if it can't find any.
func (d *DeviceManager) GetDeviceByID(id string) (*Device, error) {
	idC := C.CString(id)
	defer C.free(unsafe.Pointer(idC))

	timeout := C.gint(defaultDeviceTimeout)

	var err *C.GError
	device := C.frida_device_manager_get_device_by_id_sync(d.manager, idC, timeout, nil, &err)
	if err != nil {
		return nil, &FridaError{err}
	}
	return &Device{device: device}, nil
}

// GetDeviceType will return device or an error by device type specified.
func (d *DeviceManager) GetDeviceByType(devType DeviceType) (*Device, error) {
	var err *C.GError
	device := C.frida_device_manager_get_device_by_type_sync(d.manager,
		C.FridaDeviceType(devType),
		1,
		nil,
		&err)
	if err != nil {
		return nil, &FridaError{err}
	}
	return &Device{device: device}, nil
}

// FindDeviceByID will try to find the device by id specified
func (d *DeviceManager) FindDeviceByID(id string) (*Device, error) {
	devId := C.CString(id)
	defer C.free(unsafe.Pointer(devId))

	timeout := C.gint(defaultDeviceTimeout)

	var err *C.GError
	device := C.frida_device_manager_find_device_by_id_sync(d.manager,
		devId,
		timeout,
		nil,
		&err)
	if err != nil {
		return nil, &FridaError{err}
	}

	return &Device{device: device}, nil
}

// FindDeviceByType will try to find the device by device type specified
func (d *DeviceManager) FindDeviceByType(devType DeviceType) (*Device, error) {
	timeout := C.gint(defaultDeviceTimeout)

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

// Add remote address available at address with remoteOpts populated
func (d *DeviceManager) AddRemoteDevice(address string, remoteOpts *RemoteDeviceOptions) (*Device, error) {
	addressC := C.CString(address)
	defer C.free(unsafe.Pointer(addressC))

	var err *C.GError
	device := C.frida_device_manager_add_remote_device_sync(d.manager, addressC, remoteOpts.opts, nil, &err)
	if err != nil {
		return nil, &FridaError{err}
	}

	return &Device{device: device}, nil
}

// RemoveRemoteDevices removes remote device available at address
func (d *DeviceManager) RemoveRemoteDevice(address string) error {
	addressC := C.CString(address)
	defer C.free(unsafe.Pointer(addressC))

	var err *C.GError
	C.frida_device_manager_remove_remote_device_sync(d.manager,
		addressC,
		nil,
		&err)
	if err != nil {
		return &FridaError{err}
	}
	return nil
}
