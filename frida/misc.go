package frida

//#include <frida-core.h>
import "C"

import (
	"encoding/json"
	"fmt"
	"unsafe"
)

type Cancellable struct {
	cancellable *C.GCancellable
}

func NewCancellable() *Cancellable {
	return &Cancellable{
		cancellable: C.g_cancellable_new(),
	}
}

func (c *Cancellable) Cancel() {
	C.g_cancellable_cancel(c.cancellable)
}

func (c *Cancellable) Unref() {
	C.g_object_unref((C.gpointer)(c.cancellable))
}

type options struct {
	cancellable *C.GCancellable
}

func setupOptions(opts []OptFunc) options {
	o := &options{}
	for _, opt := range opts {
		opt(o)
	}
	return *o
}

type OptFunc func(o *options)

func WithCancel(cancel *Cancellable) OptFunc {
	return func(o *options) {
		o.cancellable = cancel.cancellable
	}
}

func handleGError(gErr *C.GError) error {
	if gErr == nil {
		return nil
	}
	defer clean(unsafe.Pointer(gErr), unrefGError)
	return fmt.Errorf("FError: %s", C.GoString(gErr.message))
}

// MessageType represents all possible message types populated
// in the first argument of the on_message callback.
type MessageType string

const (
	MessageTypeLog   MessageType = "log"
	MessageTypeError MessageType = "error"
	MessageTypeSend  MessageType = "send"
)

// LevelType represents possible levels when Message.Type == MessageTypeLog
type LevelType string

const (
	LevelTypeLog   LevelType = "info"
	LevelTypeWarn  LevelType = "warning"
	LevelTypeError LevelType = "error"
)

// Message represents the data returned inside the message parameter in on_message script callback
type Message struct {
	Type         MessageType `json:"type"`
	Level        LevelType   `json:"level,omitempty"`        // populated when type==MessageTypeLog
	Description  string      `json:"description,omitempty"`  // populated when type==MessageTypeError
	Stack        string      `json:"stack,omitempty"`        // populated when type==MessageTypeError
	Filename     string      `json:"fileName,omitempty"`     // populated when type==MessageTypeError
	LineNumber   int         `json:"lineNumber,omitempty"`   // populated when type==MessageTypeError
	ColumnNumber int         `json:"columnNumber,omitempty"` // populated when type==MessageTypeError
	Payload      any         `json:"payload,omitempty"`
	IsPayloadMap bool
}

// ScriptMessageToMessage returns the parsed Message from the message string received in
// script.On("message", func(msg string, data []byte) {}) callback.
func ScriptMessageToMessage(message string) (*Message, error) {
	var m Message
	if err := json.Unmarshal([]byte(message), &m); err != nil {
		return nil, err
	}
	if m.Type != MessageTypeError {
		var payload map[string]any
		if err := json.Unmarshal([]byte(m.Payload.(string)), &payload); err == nil {
			m.Payload = payload
			m.IsPayloadMap = true
		}
	}
	return &m, nil
}
