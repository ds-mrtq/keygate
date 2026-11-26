package wingui

import (
	"sync"
	"time"
)

// balloonGap is how long a tray balloon stays before the next one may replace it.
const balloonGap = 5 * time.Second

// maxQueuedBalloons bounds the queue; the oldest waiting balloon is dropped first.
const maxQueuedBalloons = 4

// balloonQueue spaces tray balloons. Windows shows one balloon per icon and a new one replaces the
// current at once, so a balloon posted right after another was never seen (a refused start-up
// unlock followed 1 ms later by the Hello prompt of a request that was waiting for the unlock).
type balloonQueue struct {
	mu       sync.Mutex
	gap      time.Duration
	now      func() time.Time
	q        [][2]string
	last     time.Time // when the last balloon was shown
	lastItem [2]string
	armed    bool // a show is scheduled or in progress
}

func newBalloonQueue(gap time.Duration, now func() time.Time) *balloonQueue {
	return &balloonQueue{gap: gap, now: now}
}

// add queues a balloon. When sched is true the caller must run next after delay; otherwise a show
// is already scheduled (or the balloon repeats the one on screen / the last one queued).
func (b *balloonQueue) add(title, text string) (delay time.Duration, sched bool) {
	item := [2]string{title, text}
	b.mu.Lock()
	defer b.mu.Unlock()
	if n := len(b.q); n > 0 && b.q[n-1] == item {
		return 0, false
	}
	if len(b.q) == 0 && item == b.lastItem && b.now().Sub(b.last) < b.gap {
		return 0, false // the same balloon is still showing
	}
	if len(b.q) >= maxQueuedBalloons {
		b.q = b.q[1:]
	}
	b.q = append(b.q, item)
	if b.armed {
		return 0, false
	}
	b.armed = true
	return b.waitLocked(), true
}

// hint is a balloon only worth showing at once (the Hello dialog it announces is already on
// screen and may be answered before a delayed balloon appears): it is dropped instead of queued
// while another balloon is showing or waiting. sched true = the caller must run next now.
func (b *balloonQueue) hint(title, text string) (sched bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.armed || len(b.q) > 0 || b.waitLocked() > 0 {
		return false
	}
	b.q = append(b.q, [2]string{title, text})
	b.armed = true
	return true
}

func (b *balloonQueue) waitLocked() time.Duration {
	if b.last.IsZero() {
		return 0
	}
	if d := b.gap - b.now().Sub(b.last); d > 0 {
		return d
	}
	return 0
}

// next takes the balloon to show now. more reports that another one waits and must be shown after
// delay (the caller schedules it).
func (b *balloonQueue) next() (item [2]string, ok bool, delay time.Duration, more bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.q) == 0 {
		b.armed = false
		return item, false, 0, false
	}
	item, b.q = b.q[0], b.q[1:]
	b.last, b.lastItem = b.now(), item
	if len(b.q) == 0 {
		b.armed = false
		return item, true, 0, false
	}
	return item, true, b.gap, true
}
