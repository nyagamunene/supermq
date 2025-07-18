// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

//go:build !test

package api

import (
	"context"
	"log/slog"
	"time"

	"github.com/absmach/supermq/coap"
	"github.com/absmach/supermq/pkg/messaging"
)

var _ coap.Service = (*loggingMiddleware)(nil)

type loggingMiddleware struct {
	logger *slog.Logger
	svc    coap.Service
}

// LoggingMiddleware adds logging facilities to the adapter.
func LoggingMiddleware(svc coap.Service, logger *slog.Logger) coap.Service {
	return &loggingMiddleware{logger, svc}
}

// Publish logs the publish request. It logs the channel ID, subtopic (if any) and the time it took to complete the request.
// If the request fails, it logs the error.
func (lm *loggingMiddleware) Publish(ctx context.Context, key string, msg *messaging.Message) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("channel_id", msg.GetChannel()),
			slog.String("domain_id", msg.GetDomain()),
		}
		if msg.GetSubtopic() != "" {
			args = append(args, slog.String("subtopic", msg.GetSubtopic()))
		}
		if err != nil {
			args = append(args, slog.String("error", err.Error()))
			lm.logger.Warn("Publish message failed", args...)
			return
		}
		lm.logger.Info("Publish message completed successfully", args...)
	}(time.Now())

	return lm.svc.Publish(ctx, key, msg)
}

// Subscribe logs the subscribe request. It logs the channel ID, subtopic (if any) and the time it took to complete the request.
// If the request fails, it logs the error.
func (lm *loggingMiddleware) Subscribe(ctx context.Context, key, domainID, chanID, subtopic string, c coap.Client) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("channel_id", chanID),
			slog.String("domain_id", domainID),
		}
		if subtopic != "" {
			args = append(args, slog.String("subtopic", subtopic))
		}
		if err != nil {
			args = append(args, slog.String("error", err.Error()))
			lm.logger.Warn("Subscribe failed", args...)
			return
		}
		lm.logger.Info("Subscribe completed successfully", args...)
	}(time.Now())

	return lm.svc.Subscribe(ctx, key, domainID, chanID, subtopic, c)
}

// Unsubscribe logs the unsubscribe request. It logs the channel ID, subtopic (if any) and the time it took to complete the request.
// If the request fails, it logs the error.
func (lm *loggingMiddleware) Unsubscribe(ctx context.Context, key, domainID, chanID, subtopic, token string) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("channel_id", chanID),
			slog.String("domain_id", domainID),
		}
		if subtopic != "" {
			args = append(args, slog.String("subtopic", subtopic))
		}
		if err != nil {
			args = append(args, slog.String("error", err.Error()))
			lm.logger.Warn("Unsubscribe failed", args...)
			return
		}
		lm.logger.Info("Unsubscribe completed successfully", args...)
	}(time.Now())

	return lm.svc.Unsubscribe(ctx, key, domainID, chanID, subtopic, token)
}

// DisconnectHandler logs the disconnect handler. It logs the channel ID, subtopic (if any) and the time it took to complete the request.
// If the request fails, it logs the error.
func (lm *loggingMiddleware) DisconnectHandler(ctx context.Context, domainID, chanID, subtopic, token string) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("domain_id", domainID),
			slog.String("channel_id", chanID),
			slog.String("token", token),
		}
		if subtopic != "" {
			args = append(args, slog.String("subtopic", subtopic))
		}
		if err != nil {
			args = append(args, slog.String("error", err.Error()))
			lm.logger.Warn("Unsubscribe failed", args...)
			return
		}
		lm.logger.Info("Unsubscribe completed successfully", args...)
	}(time.Now())

	return lm.svc.DisconnectHandler(ctx, domainID, chanID, subtopic, token)
}
