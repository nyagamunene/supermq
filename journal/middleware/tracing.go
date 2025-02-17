// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"context"
	"fmt"
	"strings"

	"github.com/absmach/supermq/journal"
	smqauthn "github.com/absmach/supermq/pkg/authn"
	"github.com/go-chi/chi/v5/middleware"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

const (
	separator   = "-"
	emptyString = ""
)

var _ journal.Service = (*tracing)(nil)

type tracing struct {
	tracer trace.Tracer
	svc    journal.Service
}

func Tracing(svc journal.Service, tracer trace.Tracer) journal.Service {
	return &tracing{tracer, svc}
}

func (tm *tracing) startSpan(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	reqID := middleware.GetReqID(ctx)
	if reqID != "" {
		cleanID := strings.ReplaceAll(reqID, separator, emptyString)
		final := fmt.Sprintf("%032s", cleanID)
		if traceID, err := trace.TraceIDFromHex(final); err == nil {
			spanCtx := trace.NewSpanContext(trace.SpanContextConfig{
				TraceID:    traceID,
				SpanID:     trace.SpanID{},
				TraceFlags: trace.FlagsSampled,
			})
			ctx = trace.ContextWithSpanContext(ctx, spanCtx)
		}
	}

	opts = append(opts, trace.WithAttributes(attribute.String("request_id", reqID)))
	return tm.tracer.Start(ctx, name, opts...)
}

func (tm *tracing) Save(ctx context.Context, j journal.Journal) error {
	ctx, span := tm.startSpan(ctx, "save", trace.WithAttributes(
		attribute.String("occurred_at", j.OccurredAt.String()),
		attribute.String("operation", j.Operation),
	))
	defer span.End()

	return tm.svc.Save(ctx, j)
}

func (tm *tracing) RetrieveAll(ctx context.Context, session smqauthn.Session, page journal.Page) (resp journal.JournalsPage, err error) {
	ctx, span := tm.startSpan(ctx, "retrieve_all", trace.WithAttributes(
		attribute.Int64("offset", int64(page.Offset)),
		attribute.Int64("limit", int64(page.Limit)),
		attribute.Int64("total", int64(resp.Total)),
		attribute.String("entity_type", page.EntityType.String()),
		attribute.String("operation", page.Operation),
	))
	defer span.End()

	return tm.svc.RetrieveAll(ctx, session, page)
}

func (tm *tracing) RetrieveClientTelemetry(ctx context.Context, session smqauthn.Session, clientID string) (j journal.ClientTelemetry, err error) {
	ctx, span := tm.startSpan(ctx, "retrieve", trace.WithAttributes(
		attribute.String("client_id", clientID),
		attribute.String("domain_id", session.DomainID),
	))
	defer span.End()

	return tm.svc.RetrieveClientTelemetry(ctx, session, clientID)
}
