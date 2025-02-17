// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package tracing

import (
	"context"
	"fmt"
	"strings"

	"github.com/absmach/supermq/certs"
	"github.com/go-chi/chi/v5/middleware"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

const (
	separator   = "-"
	emptyString = ""
)

var _ certs.Service = (*tracingMiddleware)(nil)

type tracingMiddleware struct {
	tracer trace.Tracer
	svc    certs.Service
}

// New returns a new certs service with tracing capabilities.
func New(svc certs.Service, tracer trace.Tracer) certs.Service {
	return &tracingMiddleware{tracer, svc}
}

func (tm *tracingMiddleware) startSpan(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
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


// IssueCert traces the "IssueCert" operation of the wrapped certs.Service.
func (tm *tracingMiddleware) IssueCert(ctx context.Context, domainID, token, clientID, ttl string) (certs.Cert, error) {
	ctx, span := tm.startSpan(ctx, "svc_create_group", trace.WithAttributes(
		attribute.String("client_id", clientID),
		attribute.String("ttl", ttl),
	))
	defer span.End()

	return tm.svc.IssueCert(ctx, domainID, token, clientID, ttl)
}

// ListCerts traces the "ListCerts" operation of the wrapped certs.Service.
func (tm *tracingMiddleware) ListCerts(ctx context.Context, clientID string, pm certs.PageMetadata) (certs.CertPage, error) {
	ctx, span := tm.startSpan(ctx, "svc_list_certs", trace.WithAttributes(
		attribute.String("client_id", clientID),
		attribute.Int64("offset", int64(pm.Offset)),
		attribute.Int64("limit", int64(pm.Limit)),
	))
	defer span.End()

	return tm.svc.ListCerts(ctx, clientID, pm)
}

// ListSerials traces the "ListSerials" operation of the wrapped certs.Service.
func (tm *tracingMiddleware) ListSerials(ctx context.Context, clientID string, pm certs.PageMetadata) (certs.CertPage, error) {
	ctx, span := tm.startSpan(ctx, "svc_list_serials", trace.WithAttributes(
		attribute.String("client_id", clientID),
		attribute.Int64("offset", int64(pm.Offset)),
		attribute.Int64("limit", int64(pm.Limit)),
	))
	defer span.End()

	return tm.svc.ListSerials(ctx, clientID, pm)
}

// ViewCert traces the "ViewCert" operation of the wrapped certs.Service.
func (tm *tracingMiddleware) ViewCert(ctx context.Context, serialID string) (certs.Cert, error) {
	ctx, span := tm.startSpan(ctx, "svc_view_cert", trace.WithAttributes(
		attribute.String("serial_id", serialID),
	))
	defer span.End()

	return tm.svc.ViewCert(ctx, serialID)
}

// RevokeCert traces the "RevokeCert" operation of the wrapped certs.Service.
func (tm *tracingMiddleware) RevokeCert(ctx context.Context, domainID, token, serialID string) (certs.Revoke, error) {
	ctx, span := tm.startSpan(ctx, "svc_revoke_cert", trace.WithAttributes(
		attribute.String("serial_id", serialID),
	))
	defer span.End()

	return tm.svc.RevokeCert(ctx, domainID, token, serialID)
}
