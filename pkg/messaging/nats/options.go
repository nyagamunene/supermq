// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package nats

import (
	"errors"
	"time"

	"github.com/absmach/supermq/pkg/messaging"
	"github.com/nats-io/nats.go/jetstream"
)

var (
	// ErrInvalidType is returned when the provided value is not of the expected type.
	ErrInvalidType = errors.New("invalid type")
)

// SMQJetStreamConfig extends jetstream.StreamConfig with slow consumer monitoring settings
type SMQJetStreamConfig struct {
	jetstream.StreamConfig
	
	SlowConsumer SlowConsumerConfig `json:"slow_consumer,omitempty"`
}

type SlowConsumerConfig struct {
	// MaxPendingBytes maps to JetStream ConsumerConfig.MaxRequestMaxBytes
	// Controls the maximum bytes per batch request (closest JetStream equivalent)
	MaxPendingBytes int `json:"max_pending_bytes,omitempty"`

	// EnableDroppedMsgTracking enables logging of message redeliveries
	// which can indicate slow consumer behavior in JetStream
	EnableDroppedMsgTracking bool `json:"enable_dropped_msg_tracking,omitempty"`
}

var (
	defaultJetStreamConfig = SMQJetStreamConfig{
		StreamConfig: jetstream.StreamConfig{
			Name:              "m",
			Description:       "SuperMQ stream for sending and receiving messages in between SuperMQ channels",
			Subjects:          []string{"m.>"},
			Retention:         jetstream.LimitsPolicy,
			MaxMsgsPerSubject: 1e6,
			MaxAge:            time.Hour * 24,
			MaxMsgSize:        1024 * 1024,
			Discard:           jetstream.DiscardOld,
			Storage:           jetstream.FileStorage,
			ConsumerLimits: jetstream.StreamConsumerLimits{
				MaxAckPending: defaultMaxPendingMsgs,
			},
		},
		SlowConsumer: SlowConsumerConfig{
			MaxPendingBytes:          defaultMaxPendingBytes,
			EnableDroppedMsgTracking: defaultEnableDroppedMsgTracking,
		},
	}
)

const (
	msgPrefix                       = "m"
	defaultMaxPendingMsgs           = 1000
	defaultMaxPendingBytes          = 5 * 1024 * 1024
	defaultEnableDroppedMsgTracking = true
)

type options struct {
	prefix             string
	jsStreamConfig     SMQJetStreamConfig
}

func defaultOptions() options {
	return options{
		prefix:         msgPrefix,
		jsStreamConfig: defaultJetStreamConfig,
	}
}

// Prefix sets the prefix for the publisher or subscriber.
func Prefix(prefix string) messaging.Option {
	return func(val any) error {
		switch v := val.(type) {
		case *publisher:
			v.prefix = prefix
		case *pubsub:
			v.prefix = prefix
		default:
			return ErrInvalidType
		}

		return nil
	}
}

// JSStreamConfig sets the JetStream configuration for the publisher or subscriber.
func JSStreamConfig(jsStreamConfig SMQJetStreamConfig) messaging.Option {
	return func(val any) error {
		switch v := val.(type) {
		case *publisher:
			v.jsStreamConfig = jsStreamConfig
		case *pubsub:
			v.jsStreamConfig = jsStreamConfig
		default:
			return ErrInvalidType
		}

		return nil
	}
}

// WithSlowConsumerConfig sets the slow consumer configuration within the JetStream config.
func WithSlowConsumerConfig(config SlowConsumerConfig) messaging.Option {
	return func(val interface{}) error {
		switch v := val.(type) {
		case *publisher:
			v.jsStreamConfig.SlowConsumer = config
		case *pubsub:
			v.jsStreamConfig.SlowConsumer = config
		default:
			return ErrInvalidType
		}

		return nil
	}
}

// WithConsumerLimits sets the built-in JetStream consumer limits (MaxAckPending, etc.).
func WithConsumerLimits(limits jetstream.StreamConsumerLimits) messaging.Option {
	return func(val interface{}) error {
		switch v := val.(type) {
		case *publisher:
			v.jsStreamConfig.ConsumerLimits = limits
		case *pubsub:
			v.jsStreamConfig.ConsumerLimits = limits
		default:
			return ErrInvalidType
		}

		return nil
	}
}
