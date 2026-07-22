package pipeline

import (
	"errors"
	"sync"
	"time"
)

var (
	ErrCircuitOpen = errors.New("circuit_breaker: circuit is open")
)

type State int8

const (
	StateClosed State = iota
	StateHalfOpen
	StateOpen
)

func (s State) String() string {
	switch s {
	case StateClosed:
		return "CLOSED"
	case StateHalfOpen:
		return "HALF-OPEN"
	case StateOpen:
		return "OPEN"
	default:
		return "UNKNOWN"
	}
}

// CircuitBreakerConfig defines threshold settings for state transitions.
type CircuitBreakerConfig struct {
	MaxFailures         uint32
	ResetTimeout        time.Duration
	HalfOpenMaxRequests uint32
}

// CircuitBreaker protects downstream services (e.g. LLM API calls) from cascading failures.
type CircuitBreaker struct {
	mu                  sync.Mutex
	cfg                 CircuitBreakerConfig
	state               State
	consecutiveFailures uint32
	halfOpenRequests    uint32
	lastStateChange     time.Time
}

func NewCircuitBreaker(cfg CircuitBreakerConfig) *CircuitBreaker {
	if cfg.MaxFailures == 0 {
		cfg.MaxFailures = 5
	}
	if cfg.ResetTimeout <= 0 {
		cfg.ResetTimeout = 10 * time.Second
	}
	if cfg.HalfOpenMaxRequests == 0 {
		cfg.HalfOpenMaxRequests = 2
	}

	return &CircuitBreaker{
		cfg:             cfg,
		state:           StateClosed,
		lastStateChange: time.Now().UTC(),
	}
}

func (cb *CircuitBreaker) State() State {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.checkStateTransitionLocked()
	return cb.state
}

// Execute wraps a function call in circuit breaker logic.
func (cb *CircuitBreaker) Execute(fn func() error) error {
	if err := cb.beforeExecution(); err != nil {
		return err
	}

	err := fn()
	cb.afterExecution(err)
	return err
}

func (cb *CircuitBreaker) beforeExecution() error {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.checkStateTransitionLocked()

	switch cb.state {
	case StateOpen:
		return ErrCircuitOpen
	case StateHalfOpen:
		if cb.halfOpenRequests >= cb.cfg.HalfOpenMaxRequests {
			return ErrCircuitOpen
		}
		cb.halfOpenRequests++
		return nil
	case StateClosed:
		return nil
	default:
		return nil
	}
}

func (cb *CircuitBreaker) afterExecution(err error) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if err != nil {
		cb.consecutiveFailures++
		if cb.state == StateHalfOpen || cb.consecutiveFailures >= cb.cfg.MaxFailures {
			cb.setStateLocked(StateOpen)
		}
	} else {
		if cb.state == StateHalfOpen {
			cb.setStateLocked(StateClosed)
		} else if cb.state == StateClosed {
			cb.consecutiveFailures = 0
		}
	}
}

func (cb *CircuitBreaker) checkStateTransitionLocked() {
	now := time.Now().UTC()
	if cb.state == StateOpen && now.Sub(cb.lastStateChange) >= cb.cfg.ResetTimeout {
		cb.setStateLocked(StateHalfOpen)
	}
}

func (cb *CircuitBreaker) setStateLocked(newState State) {
	cb.state = newState
	cb.lastStateChange = time.Now().UTC()
	if newState == StateClosed {
		cb.consecutiveFailures = 0
		cb.halfOpenRequests = 0
	} else if newState == StateHalfOpen {
		cb.halfOpenRequests = 0
	}
}
