// Package frida provides golang binding for frida.
package frida

/*
#cgo LDFLAGS: -lfrida-core -lm -ldl -lpthread -lresolv
#cgo CFLAGS: -I/usr/local/include/ -w
#cgo darwin LDFLAGS: -lbsm -framework Foundation -framework AppKit
#cgo linux LDFLAGS: -lrt
#cgo linux CFLAGS: -pthread
#include <frida-core.h>
*/
import "C"
import (
	"sync"
)

var data = &sync.Map{}

// Shutdown function shuts down frida
func Shutdown() {
	C.frida_shutdown()
}

// Deinit function deinitializes frida by calling frida_deinit
func Deinit() {
	C.frida_deinit()
}

// Version returns currently used frida version
func Version() string {
	return C.GoString(C.frida_version_string())
}

func getDeviceManager() *DeviceManager {
	v, ok := data.Load("mgr")
	if !ok {
		mgr := NewDeviceManager()
		data.Store("mgr", mgr)
		return mgr
	}
	return v.(*DeviceManager)
}

func LocalDevice() *Device {
	mgr := getDeviceManager()
	v, ok := data.Load("localDevice")
	if !ok {
		dev, _ := mgr.DeviceByType(DeviceTypeLocal)
		data.Store("localDevice", dev)
		return dev
	}
	return v.(*Device)
}

func USBDevice() *Device {
	mgr := getDeviceManager()
	v, ok := data.Load("usbDevice")
	if !ok {
		_, ok := data.Load("enumeratedDevices")
		if !ok {
			mgr.EnumerateDevices()
			data.Store("enumeratedDevices", true)
		}
		dev, err := mgr.DeviceByType(DeviceTypeUsb)
		if err != nil {
			return nil
		}
		data.Store("usbDevice", dev)
		return dev
	}
	return v.(*Device)
}

func Attach(val interface{}) (*Session, error) {
	dev := LocalDevice()
	return dev.Attach(val, nil)
}
