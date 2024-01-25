package frida

//#include <frida-core.h>
import "C"

import "unsafe"

// DeviceManager is the device DeviceManager interface
type DeviceManager interface {
	Close() error
	EnumerateDevices() ([]Device, error)
	LocalDevice() (Device, error)
	USBDevice() (Device, error)
	RemoteDevice() (Device, error)
	DeviceByID(id string) (Device, error)
	DeviceByType(devType DeviceType) (Device, error)
	FindDeviceByID(id string) (Device, error)
	FindDeviceByType(devType DeviceType) (Device, error)
	AddRemoteDevice(address string, remoteOpts *RemoteDeviceOptions) (Device, error)
	RemoveRemoteDevice(address string) error
	Clean()
	On(sigName string, fn any)

	getManager() *C.FridaDeviceManager
}

// deviceManager is the main structure which holds on devices available to Frida
// Single instance of the deviceManager is created when you call frida.Attach() or frida.LocalDevice().
type deviceManager struct {
	manager *C.FridaDeviceManager
}

// NewDeviceManager returns new frida device manager.
func NewDeviceManager() DeviceManager {
	manager := C.frida_device_manager_new()
	return &deviceManager{manager}
}

// Close method will close current manager.
func (d *deviceManager) Close() error {
	var err *C.GError
	C.frida_device_manager_close_sync(d.manager, nil, &err)
	if err != nil {
		return &FError{err}
	}
	return nil
}

// EnumerateDevices will return all connected devices.
func (d *deviceManager) EnumerateDevices() ([]Device, error) {
	var err *C.GError
	deviceList := C.frida_device_manager_enumerate_devices_sync(d.manager, nil, &err)
	if err != nil {
		return nil, &FError{err}
	}

	numDevices := int(C.frida_device_list_size(deviceList))
	devices := make([]Device, numDevices)

	for i := 0; i < numDevices; i++ {
		device := C.frida_device_list_get(deviceList, C.gint(i))
		devices[i] = &DeviceImpl{device}
	}

	clean(unsafe.Pointer(deviceList), unrefFrida)
	return devices, nil
}

// LocalDevice returns the device with type DeviceTypeLocal.
func (d *deviceManager) LocalDevice() (Device, error) {
	return d.DeviceByType(DeviceTypeLocal)
}

// USBDevice returns the device with type DeviceTypeUsb.
func (d *deviceManager) USBDevice() (Device, error) {
	return d.DeviceByType(DeviceTypeUsb)
}

// RemoteDevice returns the device with type DeviceTypeRemote.
func (d *deviceManager) RemoteDevice() (Device, error) {
	return d.DeviceByType(DeviceTypeRemote)
}

// DeviceByID will return device with id passed or an error if it can't find any.
// Note: the caller must call EnumerateDevices() to get devices that are of type usb
func (d *deviceManager) DeviceByID(id string) (Device, error) {
	idC := C.CString(id)
	defer C.free(unsafe.Pointer(idC))

	timeout := C.gint(defaultDeviceTimeout)

	var err *C.GError
	device := C.frida_device_manager_get_device_by_id_sync(d.manager, idC, timeout, nil, &err)
	if err != nil {
		return nil, &FError{err}
	}
	return &DeviceImpl{device: device}, nil
}

// DeviceByType will return device or an error by device type specified.
// Note: the caller must call EnumerateDevices() to get devices that are of type usb
func (d *deviceManager) DeviceByType(devType DeviceType) (Device, error) {
	var err *C.GError
	device := C.frida_device_manager_get_device_by_type_sync(d.manager,
		C.FridaDeviceType(devType),
		1,
		nil,
		&err)
	if err != nil {
		return nil, &FError{err}
	}
	return &DeviceImpl{device: device}, nil
}

// FindDeviceByID will try to find the device by id specified
// Note: the caller must call EnumerateDevices() to get devices that are of type usb
func (d *deviceManager) FindDeviceByID(id string) (Device, error) {
	devID := C.CString(id)
	defer C.free(unsafe.Pointer(devID))

	timeout := C.gint(defaultDeviceTimeout)

	var err *C.GError
	device := C.frida_device_manager_find_device_by_id_sync(d.manager,
		devID,
		timeout,
		nil,
		&err)
	if err != nil {
		return nil, &FError{err}
	}

	return &DeviceImpl{device: device}, nil
}

// FindDeviceByType will try to find the device by device type specified
// Note: the caller must call EnumerateDevices() to get devices that are of type usb
func (d *deviceManager) FindDeviceByType(devType DeviceType) (Device, error) {
	timeout := C.gint(defaultDeviceTimeout)

	var err *C.GError
	device := C.frida_device_manager_find_device_by_type_sync(d.manager,
		C.FridaDeviceType(devType),
		C.gint(timeout),
		nil,
		&err)
	if err != nil {
		return nil, &FError{err}
	}

	return &DeviceImpl{device: device}, nil
}

// AddRemoteDevice add a remote device from the provided address with remoteOpts populated
func (d *deviceManager) AddRemoteDevice(address string, remoteOpts *RemoteDeviceOptions) (Device, error) {
	addressC := C.CString(address)
	defer C.free(unsafe.Pointer(addressC))

	var err *C.GError
	device := C.frida_device_manager_add_remote_device_sync(d.manager, addressC, remoteOpts.opts, nil, &err)
	if err != nil {
		return nil, &FError{err}
	}

	return &DeviceImpl{device: device}, nil
}

// RemoveRemoteDevice removes remote device available at address
func (d *deviceManager) RemoveRemoteDevice(address string) error {
	addressC := C.CString(address)
	defer C.free(unsafe.Pointer(addressC))

	var err *C.GError
	C.frida_device_manager_remove_remote_device_sync(d.manager,
		addressC,
		nil,
		&err)
	if err != nil {
		return &FError{err}
	}
	return nil
}

// Clean will clean the resources held by the manager.
func (d *deviceManager) Clean() {
	clean(unsafe.Pointer(d.manager), unrefFrida)
}

// On connects manager to specific signals. Once sigName is triggered,
// fn callback will be called with parameters populated.
//
// Signals available are:
//   - "added" with callback as func(device *frida.Device) {}
//   - "removed" with callback as func(device *frida.Device) {}
//   - "changed" with callback as func() {}
func (d *deviceManager) On(sigName string, fn any) {
	connectClosure(unsafe.Pointer(d.manager), sigName, fn)
}

func (d *deviceManager) getManager() *C.FridaDeviceManager {
	return d.manager
}
