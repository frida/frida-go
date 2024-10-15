package frida

//#include <frida-core.h>
import "C"

import (
	"context"
	"encoding/json"
	"fmt"
	"unsafe"
)

type Cancellable struct {
	cancellable *C.GCancellable
}

// NewCancellable wraps GCancellable
// used to provide ability to cancel frida funcs.
// Reminder that the caller must either `Cancellable.Cancel()` or
// `Cancellable.Unref()` to unref the underlying C data.
func NewCancellable() *Cancellable {
	return &Cancellable{
		cancellable: C.g_cancellable_new(),
	}
}

// Cancel sends the cancel signal to GCancellable
// as well unrefs
func (c *Cancellable) Cancel() {
	C.g_cancellable_cancel(c.cancellable)
}

// Unref unrefs the wrapped GCancellable
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

// WithCancel is inteded to be used a varadic option.
// Provides the ability to to pass GCancellable to
// frida functions.
//
// Note: it is advisable to use the `FuncCtx`
// version of functions rather than handling this yourself.
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

func handleWithContext(ctx context.Context, f func(c *Cancellable, done chan any, errC chan error)) (any, error) {
	doneC := make(chan any, 1)
	errC := make(chan error, 1)

	c := NewCancellable()
	go f(c, doneC, errC)

	for {
		select {
		case <-ctx.Done():
			c.Cancel()
			return nil, ErrContextCancelled
		case done := <-doneC:
			c.Unref()
			return done, nil
		case err := <-errC:
			c.Unref()
			return nil, err
		}
	}
}
