package logger

import (
	"fmt"
	"sync"
	"time"
)

type Level string

const (
	Info  Level = "info"
	Ok    Level = "ok"
	Warn  Level = "warn"
	Error Level = "error"
)

type Entry struct {
	Time    string `json:"time"`
	Level   Level  `json:"level"`
	Message string `json:"message"`
}

type Broadcaster struct {
	mu      sync.RWMutex
	subs    []chan Entry
}

var Global = &Broadcaster{}

func (b *Broadcaster) Subscribe() chan Entry {
	b.mu.Lock()
	defer b.mu.Unlock()
	ch := make(chan Entry, 500)
	b.subs = append(b.subs, ch)
	return ch
}

func (b *Broadcaster) Unsubscribe(ch chan Entry) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for i, c := range b.subs {
		if c == ch {
			b.subs = append(b.subs[:i], b.subs[i+1:]...)
			close(ch)
			return
		}
	}
}

func (b *Broadcaster) Write(level Level, msg string, args ...interface{}) {
	entry := Entry{
		Time:    time.Now().Format("15:04:05"),
		Level:   level,
		Message: fmt.Sprintf(msg, args...),
	}
	b.mu.RLock()
	for _, ch := range b.subs {
		select {
		case ch <- entry:
		default:
		}
	}
	b.mu.RUnlock()
}
