package frida

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type rpcTestCancellingArgument struct {
	cancel context.CancelFunc
}

func rpcTestContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func rpcTestReply(t *testing.T, id, status string, value any) string {
	t.Helper()
	message, err := json.Marshal(struct {
		Type    string `json:"type"`
		Payload []any  `json:"payload"`
	}{Type: "send", Payload: []any{"frida:rpc", id, status, value}})
	if err != nil {
		t.Fatal(err)
	}
	return string(message)
}

func rpcTestPending(p *pendingScriptRPCCalls) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.callsByID)
}

func rpcTestReceive[T any](t *testing.T, ctx context.Context, results <-chan T) T {
	t.Helper()
	select {
	case value := <-results:
		return value
	case <-ctx.Done():
		t.Fatal("timed out waiting for RPC")
		var zero T
		return zero
	}
}

func TestRPCLegacyReplyValues(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status string
		value  any
		data   []byte
	}{
		{"string", "ok", "boom", nil},
		{"number", "ok", float64(42), nil},
		{"null", "ok", nil, nil},
		{"object", "ok", map[string]any{"answer": float64(42)}, nil},
		{"array", "ok", []any{"text", float64(1)}, nil},
		{"exception string", "error", "boom", nil},
		{"missing export string", "error", "unable to find method 'missing'", nil},
		{"primitive exception", "error", nil, nil},
		{"binary remains null", "ok", nil, []byte{1, 2}},
		{"empty binary remains null", "ok", nil, []byte{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var script Script
			value := script.callExport(rpcTestContext(t), "method", nil, func(_ context.Context, request scriptRPCRequest) error {
				if request.ID == "" || request.Method != "method" || len(request.Args) != 0 {
					t.Fatalf("request = %#v", request)
				}
				script.dispatchMessage(rpcTestReply(t, request.ID, tc.status, tc.value), tc.data)
				return nil
			})
			if !reflect.DeepEqual(value, tc.value) || rpcTestPending(&script.pendingCalls) != 0 {
				t.Fatalf("reply = %#v, want %#v; %d pending", value, tc.value, rpcTestPending(&script.pendingCalls))
			}
		})
	}
}

func TestRPCArgumentForwarding(t *testing.T) {
	var script Script
	value := script.callExport(rpcTestContext(t), "sum", []any{1, 2}, func(_ context.Context, request scriptRPCRequest) error {
		if request.Method != "sum" || !reflect.DeepEqual(request.Args, []any{1, 2}) {
			t.Fatalf("request = %#v", request)
		}
		script.pendingCalls.complete(scriptRPCReply{ID: request.ID, Value: nil})
		return nil
	})
	if value != nil {
		t.Fatalf("reply = %#v, want nil", value)
	}
}

func TestRPCLegacyBinaryReplyMetadata(t *testing.T) {
	var script Script
	reply := script.pendingCalls.register("id")
	script.dispatchMessage(`{"type":"send","payload":["frida:rpc","id","ok",null,"metadata"]}`, []byte{3})
	if value := rpcTestReceive(t, rpcTestContext(t), reply); value != nil {
		t.Fatalf("binary tuple = %#v, want nil", value)
	}
}

func TestRPCMessageRouting(t *testing.T) {
	for _, tc := range []struct {
		name    string
		message string
		forward bool
	}{
		{"marker log", `{"type":"log","payload":"frida:rpc"}`, true},
		{"marker error", `{"type":"error","description":"frida:rpc"}`, true},
		{"string payload", `{"type":"send","payload":"frida:rpc"}`, true},
		{"application array", `{"type":"send","payload":["application","frida:rpc"]}`, true},
		{"null payload", `{"type":"send","payload":null}`, true},
		{"object payload", `{"type":"send","payload":{"marker":"frida:rpc"}}`, true},
		{"invalid JSON", `{"type":"send","payload":"frida:rpc"`, true},
		{"missing type", `{"payload":["frida:rpc","id","ok",1]}`, true},
		{"short reserved", `{"type":"send","payload":["frida:rpc"]}`, false},
		{"missing value", `{"type":"send","payload":["frida:rpc","id","ok"]}`, false},
		{"numeric ID", `{"type":"send","payload":["frida:rpc",42,"ok",1]}`, false},
		{"null ID", `{"type":"send","payload":["frida:rpc",null,"ok",1]}`, false},
		{"empty ID", `{"type":"send","payload":["frida:rpc","","ok",1]}`, false},
		{"bad status type", `{"type":"send","payload":["frida:rpc","id",42,1]}`, false},
		{"unknown status", `{"type":"send","payload":["frida:rpc","id","unexpected",1]}`, false},
		{"unknown ID", `{"type":"send","payload":["frida:rpc","unknown","ok",1]}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var script Script
			reply := script.pendingCalls.register("id")
			calls := 0
			script.setMessageHandler(func(message string, data []byte) {
				calls++
				if message != tc.message || !reflect.DeepEqual(data, []byte{1}) {
					t.Errorf("forwarded message = %q, %v", message, data)
				}
			})
			script.dispatchMessage(tc.message, []byte{1})
			if (calls == 1) != tc.forward || rpcTestPending(&script.pendingCalls) != 1 {
				t.Fatalf("forwarded %d times, %d pending", calls, rpcTestPending(&script.pendingCalls))
			}
			select {
			case value := <-reply:
				t.Fatalf("unexpected message completed the call: %#v", value)
			default:
			}
			script.dispatchMessage(rpcTestReply(t, "id", "ok", "current"), nil)
			if value := rpcTestReceive(t, rpcTestContext(t), reply); value != "current" {
				t.Fatal(value)
			}
		})
	}
	var script Script
	script.dispatchMessage(`{"type":"send","payload":"no handler"}`, nil)
}

func TestRPCCancellationIgnoresLateReplies(t *testing.T) {
	var script Script
	posted := make(chan string, 1)
	post := func(_ context.Context, request scriptRPCRequest) error {
		posted <- request.ID
		return nil
	}
	ctx := rpcTestContext(t)
	cancelled, cancel := context.WithCancel(ctx)
	first := make(chan any, 1)
	go func() { first <- script.callExport(cancelled, "first", nil, post) }()
	oldID := rpcTestReceive(t, ctx, posted)
	cancel()
	if value := rpcTestReceive(t, ctx, first); value != ErrContextCancelled || rpcTestPending(&script.pendingCalls) != 0 {
		t.Fatalf("cancelled reply = %#v, %d pending", value, rpcTestPending(&script.pendingCalls))
	}
	second := make(chan any, 1)
	go func() { second <- script.callExport(ctx, "second", nil, post) }()
	newID := rpcTestReceive(t, ctx, posted)
	script.dispatchMessage(rpcTestReply(t, oldID, "ok", "stale"), nil)
	script.dispatchMessage(rpcTestReply(t, newID, "ok", "current"), nil)
	if value := rpcTestReceive(t, ctx, second); value != "current" || rpcTestPending(&script.pendingCalls) != 0 {
		t.Fatalf("next reply = %#v, %d pending", value, rpcTestPending(&script.pendingCalls))
	}
	script.dispatchMessage(rpcTestReply(t, oldID, "ok", "stale again"), nil)
	script.dispatchMessage(rpcTestReply(t, newID, "ok", "duplicate"), nil)
}

func TestRPCRepliesStayWithTheirScript(t *testing.T) {
	var first, second Script
	firstReply := first.pendingCalls.register("id")
	secondReply := second.pendingCalls.register("id")
	first.dispatchMessage(rpcTestReply(t, "id", "ok", "first"), nil)
	if value := rpcTestReceive(t, rpcTestContext(t), firstReply); value != "first" {
		t.Fatal(value)
	}
	if rpcTestPending(&second.pendingCalls) != 1 {
		t.Fatal("another script's call was removed")
	}
	second.dispatchMessage(rpcTestReply(t, "id", "ok", "second"), nil)
	if value := rpcTestReceive(t, rpcTestContext(t), secondReply); value != "second" {
		t.Fatal(value)
	}
}

func TestRPCConcurrentDuplicateReplies(t *testing.T) {
	var script Script
	reply := script.pendingCalls.register("id")
	message := rpcTestReply(t, "id", "ok", "once")
	var workers sync.WaitGroup
	for i := 0; i < 32; i++ {
		workers.Add(1)
		go func() { defer workers.Done(); script.dispatchMessage(message, nil) }()
	}
	done := make(chan struct{})
	go func() { workers.Wait(); close(done) }()
	rpcTestReceive(t, rpcTestContext(t), done)
	if value := <-reply; value != "once" || len(reply) != 0 || rpcTestPending(&script.pendingCalls) != 0 {
		t.Fatalf("duplicate reply = %#v", value)
	}
}

func TestRPCReplyCancellationRace(t *testing.T) {
	ctx := rpcTestContext(t)
	for i := 0; i < 100; i++ {
		var script Script
		cancelled, cancel := context.WithCancel(ctx)
		posted := make(chan string, 1)
		result := make(chan any, 1)
		go func() {
			result <- script.callExport(cancelled, "race", nil, func(_ context.Context, request scriptRPCRequest) error {
				posted <- request.ID
				return nil
			})
		}()
		id := rpcTestReceive(t, ctx, posted)
		message := rpcTestReply(t, id, "ok", "reply")
		var workers sync.WaitGroup
		workers.Add(2)
		go func() { defer workers.Done(); cancel() }()
		go func() { defer workers.Done(); script.dispatchMessage(message, nil) }()
		value := rpcTestReceive(t, ctx, result)
		workers.Wait()
		if value != "reply" && value != ErrContextCancelled {
			t.Fatalf("race reply = %#v", value)
		}
		if rpcTestPending(&script.pendingCalls) != 0 {
			t.Fatal("call retained after completion/cancellation")
		}
	}
}

func TestRPCCancelledCallIsNotPosted(t *testing.T) {
	var script Script
	post := func(context.Context, scriptRPCRequest) error {
		t.Error("posted a cancelled call")
		return nil
	}
	ctx, cancel := context.WithCancel(rpcTestContext(t))
	cancel()
	if value := script.callExport(ctx, "cancelled", nil, post); value != ErrContextCancelled {
		t.Fatal(value)
	}
	expired, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if value := script.callExport(expired, "expired", nil, post); value != ErrContextCancelled {
		t.Fatal(value)
	}
	if rpcTestPending(&script.pendingCalls) != 0 {
		t.Fatal("cancelled call retained")
	}
}

func TestRPCRequestEncoding(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []any
		want string
	}{
		{"no arguments", nil, `["frida:rpc","id","call","method",[]]`},
		{"arguments", []any{"text", 2}, `["frida:rpc","id","call","method",["text",2]]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := json.Marshal(scriptRPCRequest{ID: "id", Method: "method", Args: tc.args})
			if err != nil {
				t.Fatal(err)
			}
			if string(encoded) != tc.want {
				t.Fatalf("request = %s, want %s", encoded, tc.want)
			}
		})
	}
}

func TestRPCEncodingFailureRetiresCall(t *testing.T) {
	// Encoding must fail before reaching the native post on this empty Script.
	var script Script
	value := script.ExportsCallWithContext(rpcTestContext(t), "invalid", func() {})
	var encodingError *json.UnsupportedTypeError
	err, ok := value.(error)
	if !ok || !errors.As(err, &encodingError) || rpcTestPending(&script.pendingCalls) != 0 {
		t.Fatalf("encoding failure = %#v, %d pending", value, rpcTestPending(&script.pendingCalls))
	}
}

func (a rpcTestCancellingArgument) MarshalJSON() ([]byte, error) {
	a.cancel()
	return []byte("null"), nil
}

func TestRPCCancellationDuringEncodingPreventsPost(t *testing.T) {
	var script Script
	ctx, cancel := context.WithCancel(rpcTestContext(t))
	defer cancel()
	value := script.ExportsCallWithContext(ctx, "cancelled", rpcTestCancellingArgument{cancel: cancel})
	if value != ErrContextCancelled || rpcTestPending(&script.pendingCalls) != 0 {
		t.Fatalf("cancelled encoding = %#v, %d pending", value, rpcTestPending(&script.pendingCalls))
	}
}

func TestRPCMessageHandlerPublication(t *testing.T) {
	var script Script
	var calls int64
	fn := func(message string, data []byte) {
		if message != `{"type":"send","payload":"user"}` || len(data) != 1 || data[0] != 42 {
			t.Errorf("message changed: %q, %v", message, data)
		}
		atomic.AddInt64(&calls, 1)
	}
	script.setMessageHandler(fn)
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		for i := 0; i < 1000; i++ {
			script.setMessageHandler(func(message string, data []byte) { fn(message, data) })
		}
	}()
	go func() {
		defer workers.Done()
		for i := 0; i < 1000; i++ {
			script.dispatchMessage(`{"type":"send","payload":"user"}`, []byte{42})
		}
	}()
	workers.Wait()
	if count := atomic.LoadInt64(&calls); count != 1000 {
		t.Fatalf("handler called %d times", count)
	}
}
