package frida

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/google/uuid"
)

type scriptMessageEnvelope struct {
	Type    string            `json:"type"`
	Payload []json.RawMessage `json:"payload"`
}

type scriptRPCRequest struct {
	ID     string
	Method string
	Args   []any
}

type scriptRPCReply struct {
	ID    string
	Value any
}

type pendingScriptRPCCalls struct {
	mu        sync.Mutex
	callsByID map[string]chan any
}

func (p *pendingScriptRPCCalls) register(id string) <-chan any {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.callsByID == nil {
		p.callsByID = make(map[string]chan any)
	}
	// Each call owns its channel. A reply can finish delivery after cancellation.
	reply := make(chan any, 1)
	p.callsByID[id] = reply
	return reply
}

func (p *pendingScriptRPCCalls) remove(id string) chan any {
	p.mu.Lock()
	defer p.mu.Unlock()

	reply := p.callsByID[id]
	delete(p.callsByID, id)
	return reply
}

func (p *pendingScriptRPCCalls) complete(reply scriptRPCReply) {
	// Removing before delivery gives at most one reply access to the channel.
	if channel := p.remove(reply.ID); channel != nil {
		channel <- reply.Value
	}
}

func (r scriptRPCRequest) MarshalJSON() ([]byte, error) {
	args := r.Args
	if args == nil {
		args = []any{}
	}
	// Frida's RPC wire format is a positional array, not a JSON object.
	return json.Marshal([]any{"frida:rpc", r.ID, "call", r.Method, args})
}

func (s *Script) callExport(ctx context.Context, method string, args []any, post func(context.Context, scriptRPCRequest) error) any {
	if ctx.Err() != nil {
		return ErrContextCancelled
	}
	request := scriptRPCRequest{ID: uuid.NewString(), Method: method, Args: args}
	reply := s.pendingCalls.register(request.ID)
	defer s.pendingCalls.remove(request.ID)
	if ctx.Err() != nil {
		return ErrContextCancelled
	}
	if err := post(ctx, request); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ErrContextCancelled
	case value := <-reply:
		return value
	}
}

// decodeScriptRPCReply classifies a native message before decoding its reply.
// isRPC remains true for malformed reserved messages; a nil reply discards them.
func decodeScriptRPCReply(message string) (reply *scriptRPCReply, isRPC bool) {
	var envelope scriptMessageEnvelope
	if json.Unmarshal([]byte(message), &envelope) != nil || envelope.Type != "send" || len(envelope.Payload) == 0 {
		return nil, false
	}
	parts := envelope.Payload
	var marker string
	if json.Unmarshal(parts[0], &marker) != nil || marker != "frida:rpc" {
		return nil, false
	}
	return decodeScriptRPCPayload(parts[1:]), true
}

func decodeScriptRPCPayload(parts []json.RawMessage) *scriptRPCReply {
	var reply scriptRPCReply
	if len(parts) < 3 || json.Unmarshal(parts[0], &reply.ID) != nil || reply.ID == "" {
		return nil
	}
	var status string
	if json.Unmarshal(parts[1], &status) != nil || (status != "ok" && status != "error") {
		return nil
	}
	// ExportsCall returns the value for both success and error replies.
	if json.Unmarshal(parts[2], &reply.Value) != nil {
		return nil
	}
	return &reply
}
