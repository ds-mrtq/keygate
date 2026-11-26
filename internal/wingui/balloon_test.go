package wingui

import (
	"testing"
	"time"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

// A refused start-up unlock followed 1 ms later by the Hello prompt of a waiting request: both must
// be shown, the second only after the first had its gap.
func TestBalloonQueueSpacesBackToBack(t *testing.T) {
	c := &fakeClock{t: time.Unix(1000, 0)}
	q := newBalloonQueue(5*time.Second, c.now)
	if d, sched := q.add("KeyGate cần Windows Hello", "mở khóa"); !sched || d != 0 {
		t.Fatalf("first balloon: delay=%v sched=%v", d, sched)
	}
	if it, ok, _, more := q.next(); !ok || more || it[0] != "KeyGate cần Windows Hello" {
		t.Fatalf("first show: %v %v %v", it, ok, more)
	}
	c.t = c.t.Add(30 * time.Second)
	if d, sched := q.add("KeyGate chưa mở khóa", "từ chối"); !sched || d != 0 {
		t.Fatalf("refusal after a long pause must show at once: delay=%v sched=%v", d, sched)
	}
	if _, sched := q.add("KeyGate cần Windows Hello", "mở khóa"); sched {
		t.Fatal("second balloon must wait for the scheduled show, not post its own")
	}
	it, ok, delay, more := q.next()
	if !ok || it[0] != "KeyGate chưa mở khóa" || !more || delay != 5*time.Second {
		t.Fatalf("refusal must show first and keep the prompt for later: %v %v %v %v", it, ok, delay, more)
	}
	c.t = c.t.Add(delay)
	if it, ok, _, more := q.next(); !ok || more || it[0] != "KeyGate cần Windows Hello" {
		t.Fatalf("prompt after the gap: %v %v %v", it, ok, more)
	}
	if _, ok, _, _ := q.next(); ok {
		t.Fatal("queue must be empty")
	}
}

func TestBalloonQueueWaitsForGapAndDropsRepeats(t *testing.T) {
	c := &fakeClock{t: time.Unix(1000, 0)}
	q := newBalloonQueue(5*time.Second, c.now)
	q.add("a", "1")
	q.next()
	c.t = c.t.Add(2 * time.Second)
	if _, sched := q.add("a", "1"); sched {
		t.Fatal("the balloon on screen repeated must be dropped")
	}
	if d, sched := q.add("b", "2"); !sched || d != 3*time.Second {
		t.Fatalf("new balloon 2s after the last must wait 3s: %v %v", d, sched)
	}
	if _, sched := q.add("b", "2"); sched {
		t.Fatal("repeat of the queued balloon must be dropped")
	}
	for i := range 2 * maxQueuedBalloons {
		q.add("c", string(rune('0'+i)))
	}
	if len(q.q) != maxQueuedBalloons || q.q[len(q.q)-1][1] != string(rune('0'+2*maxQueuedBalloons-1)) {
		t.Fatalf("queue bounded, newest kept: %v", q.q)
	}
}
