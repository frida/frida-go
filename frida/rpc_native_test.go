//go:build integration && (darwin || linux) && !android && !ios

package frida

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func rpcNativeTarget(t *testing.T) string {
	t.Helper()
	target, err := filepath.Abs("testdata/bin/rpc-target")
	if err != nil {
		t.Fatalf("resolve native RPC target: %v", err)
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("native RPC target: %v; run make test-integration from the repository root", err)
	}
	return target
}

func rpcNativeSession(t *testing.T) (*Session, *exec.Cmd) {
	t.Helper()
	target := rpcNativeTarget(t)
	manager := NewDeviceManager()
	t.Cleanup(func() {
		if err := manager.Close(); err != nil {
			t.Error(err)
		}
		manager.Clean()
	})
	device, err := manager.DeviceByType(DeviceTypeLocal)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(device.Clean)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	process := exec.CommandContext(ctx, target)
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = process.Process.Kill(); _ = process.Wait() })
	session, err := device.Attach(process.Process.Pid, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if !session.IsDetached() {
			if err := session.Detach(); err != nil {
				t.Error(err)
			}
		}
		session.Clean()
	})
	return session, process
}

func rpcNativeScript(t *testing.T, session *Session, source string) *Script {
	t.Helper()
	script, err := session.CreateScript(source)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if !script.IsDestroyed() {
			if err := script.Unload(); err != nil {
				t.Error(err)
			}
		}
		script.Clean()
	})
	return script
}

func rpcNativeLoad(t *testing.T, script *Script) {
	t.Helper()
	if err := script.Load(); err != nil {
		t.Fatal(err)
	}
}

func TestNativeRPCLegacyValues(t *testing.T) {
	session, _ := rpcNativeSession(t)
	script := rpcNativeScript(t, session, `
 rpc.exports.text = () => 'boom';
 rpc.exports.fail = () => { throw new TypeError('boom'); };
 rpc.exports.primitive = () => { throw 'primitive'; };
 rpc.exports.number = () => 42;
 rpc.exports.object = () => ({ answer: 42 });
 rpc.exports.array = () => ['text', 1];
 rpc.exports.nil = () => null;
 rpc.exports.sum = (a, b) => a + b;
 rpc.exports.bytes = () => new Uint8Array([1, 2]).buffer;
 rpc.exports.emptyBytes = () => new ArrayBuffer(0);
 rpc.exports.tuple = () => ['metadata', new Uint8Array([3]).buffer];
 `)
	rpcNativeLoad(t, script)
	for _, tc := range []struct {
		method string
		args   []any
		want   any
	}{
		{"text", nil, "boom"},
		{"fail", nil, "boom"},
		{"primitive", nil, nil},
		{"missing", nil, "unable to find method 'missing'"},
		{"number", nil, float64(42)},
		{"object", nil, map[string]any{"answer": float64(42)}},
		{"array", nil, []any{"text", float64(1)}},
		{"nil", nil, nil},
		{"sum", []any{1, 2}, float64(3)},
		{"bytes", nil, nil},
		{"emptyBytes", nil, nil},
		{"tuple", nil, nil},
	} {
		t.Run(tc.method, func(t *testing.T) {
			if value := script.ExportsCallWithContext(rpcTestContext(t), tc.method, tc.args...); !reflect.DeepEqual(value, tc.want) {
				t.Fatalf("reply = %#v, want %#v", value, tc.want)
			}
		})
	}
	result := make(chan any, 1)
	go func() { result <- script.ExportsCall("fail") }()
	if value := rpcTestReceive(t, rpcTestContext(t), result); value != "boom" {
		t.Fatalf("ExportsCall exception = %#v", value)
	}
}

func TestNativeRPCMessageHookRegistration(t *testing.T) {
	session, _ := rpcNativeSession(t)
	first := rpcNativeScript(t, session, `rpc.exports.echo = () => 'ok';`)
	first.On("destroyed", func() {})
	rpcNativeLoad(t, first)
	if value := first.ExportsCallWithContext(rpcTestContext(t), "echo"); value != "ok" {
		t.Fatalf("RPC after registering destroyed first = %#v", value)
	}
	second := rpcNativeScript(t, session, `rpc.exports.notify = () => { send('user'); return 'ok'; };`)
	var oldCalls, calls int64
	second.On("message", func(string) { atomic.AddInt64(&oldCalls, 1) })
	second.On("message", func(string) { atomic.AddInt64(&calls, 1) })
	rpcNativeLoad(t, second)
	if value := second.ExportsCallWithContext(rpcTestContext(t), "notify"); value != "ok" {
		t.Fatalf("RPC with repeated message handlers = %#v", value)
	}
	if atomic.LoadInt64(&oldCalls) != 0 || atomic.LoadInt64(&calls) != 1 {
		t.Fatalf("message delivered %d times to old and %d to current handler", oldCalls, calls)
	}
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		for i := 0; i < 100; i++ {
			second.On("message", func(string) { atomic.AddInt64(&calls, 1) })
		}
	}()
	for i := 0; i < 100; i++ {
		if value := second.ExportsCallWithContext(rpcTestContext(t), "notify"); value != "ok" {
			t.Fatalf("RPC while replacing handler = %#v", value)
		}
	}
	workers.Wait()
	if count := atomic.LoadInt64(&calls); count != 101 {
		t.Fatalf("message handler called %d times, want 101", count)
	}
}

func TestNativeRPCUnexpectedMessages(t *testing.T) {
	session, _ := rpcNativeSession(t)
	script := rpcNativeScript(t, session, `
 rpc.exports.noise = () => {
   console.log('frida:rpc');
   send('frida:rpc');
   send(['application', 'frida:rpc']);
   send(['frida:rpc']);
   send(['frida:rpc', 42, 'ok', 'bad id']);
   send(['frida:rpc', 'unknown', 'unexpected', 'bad status']);
   send(['frida:rpc', 'unknown', 'ok', 'unknown reply']);
   send(['frida:rpc', 'unknown', 'ok', 'duplicate reply']);
   return 'current';
 };
 `)
	var calls int64
	script.On("message", func(string) { atomic.AddInt64(&calls, 1) })
	rpcNativeLoad(t, script)
	if value := script.ExportsCallWithContext(rpcTestContext(t), "noise"); value != "current" {
		t.Fatalf("RPC after unexpected messages = %#v", value)
	}
	if count := atomic.LoadInt64(&calls); count != 3 {
		t.Fatalf("forwarded %d ordinary messages, want 3", count)
	}
}

const rpcNativePending = `
 let release;
 rpc.exports.wait = () => {
   send('waiting');
   return new Promise(resolve => { release = resolve; });
 };
 rpc.exports.release = () => { release('stale'); return 'released'; };
 rpc.exports.echo = value => value;
`

func rpcNativeStartPending(t *testing.T, script *Script, ctx context.Context) <-chan any {
	t.Helper()
	started := make(chan struct{}, 1)
	script.On("message", func(string) {
		select {
		case started <- struct{}{}:
		default:
		}
	})
	result := make(chan any, 1)
	go func() { result <- script.ExportsCallWithContext(ctx, "wait") }()
	rpcTestReceive(t, rpcTestContext(t), started)
	return result
}

func TestNativeRPCCancellationAndLateReply(t *testing.T) {
	session, _ := rpcNativeSession(t)
	script := rpcNativeScript(t, session, rpcNativePending)
	rpcNativeLoad(t, script)
	ctx, cancel := context.WithCancel(rpcTestContext(t))
	result := rpcNativeStartPending(t, script, ctx)
	cancel()
	if value := rpcTestReceive(t, rpcTestContext(t), result); value != ErrContextCancelled {
		t.Fatalf("cancellation = %#v", value)
	}
	if value := script.ExportsCallWithContext(rpcTestContext(t), "release"); value != "released" {
		t.Fatalf("release after cancelled call = %#v", value)
	}
	if value := script.ExportsCallWithContext(rpcTestContext(t), "echo", "current"); value != "current" {
		t.Fatalf("reply after late completion = %#v", value)
	}
	deadline, cancel := context.WithTimeout(rpcTestContext(t), 100*time.Millisecond)
	defer cancel()
	if value := script.ExportsCallWithContext(deadline, "wait"); value != ErrContextCancelled {
		t.Fatalf("deadline = %#v", value)
	}
	if value := script.ExportsCallWithContext(rpcTestContext(t), "release"); value != "released" {
		t.Fatalf("release after deadline = %#v", value)
	}
}

func TestNativeRPCIndependentScripts(t *testing.T) {
	session, _ := rpcNativeSession(t)
	first := rpcNativeScript(t, session, `rpc.exports.echo = value => ['first', value];`)
	second := rpcNativeScript(t, session, `rpc.exports.echo = value => ['second', value];`)
	rpcNativeLoad(t, first)
	rpcNativeLoad(t, second)
	ctx := rpcTestContext(t)
	results := make(chan any, 2)
	go func() { results <- first.ExportsCallWithContext(ctx, "echo", "value") }()
	go func() { results <- second.ExportsCallWithContext(ctx, "echo", "value") }()
	seen := make(map[string]bool)
	for i := 0; i < 2; i++ {
		value := rpcTestReceive(t, ctx, results)
		tuple, ok := value.([]any)
		if !ok || len(tuple) != 2 || tuple[1] != "value" {
			t.Fatalf("independent reply = %#v", value)
		}
		name, ok := tuple[0].(string)
		if !ok || (name != "first" && name != "second") || seen[name] {
			t.Fatalf("unexpected script reply = %#v", value)
		}
		seen[name] = true
	}
}

func TestNativeRPCDetachCancelsContext(t *testing.T) {
	session, process := rpcNativeSession(t)
	script := rpcNativeScript(t, session, rpcNativePending)
	ctx, cancel := context.WithCancel(rpcTestContext(t))
	defer cancel()
	session.On("detached", func(SessionDetachReason) { cancel() })
	rpcNativeLoad(t, script)
	result := rpcNativeStartPending(t, script, ctx)
	if err := process.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if value := rpcTestReceive(t, rpcTestContext(t), result); value != ErrContextCancelled {
		t.Fatalf("detached context = %#v", value)
	}
}
