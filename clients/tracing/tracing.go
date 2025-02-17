// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package tracing

import (
	"context"
	"fmt"
	"strings"

	"github.com/absmach/supermq/clients"
	"github.com/absmach/supermq/pkg/authn"
	"github.com/absmach/supermq/pkg/roles"
	rmTrace "github.com/absmach/supermq/pkg/roles/rolemanager/tracing"
	"github.com/go-chi/chi/v5/middleware"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

const (
	separator   = "-"
	emptyString = ""
)

var _ clients.Service = (*tracingMiddleware)(nil)

type tracingMiddleware struct {
	tracer trace.Tracer
	svc    clients.Service
	rmTrace.RoleManagerTracing
}

// New returns a new group service with tracing capabilities.
func New(svc clients.Service, tracer trace.Tracer) clients.Service {
	return &tracingMiddleware{
		tracer:             tracer,
		svc:                svc,
		RoleManagerTracing: rmTrace.NewRoleManagerTracing("group", svc, tracer),
	}
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

// CreateClients traces the "CreateClients" operation of the wrapped clients.Service.
func (tm *tracingMiddleware) CreateClients(ctx context.Context, session authn.Session, cli ...clients.Client) ([]clients.Client, []roles.RoleProvision, error) {
	ctx, span := tm.startSpan(ctx, "svc_create_client")
	defer span.End()

	return tm.svc.CreateClients(ctx, session, cli...)
}

// View traces the "View" operation of the wrapped clients.Service.
func (tm *tracingMiddleware) View(ctx context.Context, session authn.Session, id string) (clients.Client, error) {
	ctx, span := tm.startSpan(ctx, "svc_view_client", trace.WithAttributes(attribute.String("id", id)))
	defer span.End()
	return tm.svc.View(ctx, session, id)
}

// ListClients traces the "ListClients" operation of the wrapped clients.Service.
func (tm *tracingMiddleware) ListClients(ctx context.Context, session authn.Session, pm clients.Page) (clients.ClientsPage, error) {
	ctx, span := tm.startSpan(ctx, "svc_list_clients")
	defer span.End()
	return tm.svc.ListClients(ctx, session, pm)
}

func (tm *tracingMiddleware) ListUserClients(ctx context.Context, session authn.Session, userID string, pm clients.Page) (clients.ClientsPage, error) {
	ctx, span := tm.startSpan(ctx, "svc_list_clients")
	defer span.End()
	return tm.svc.ListUserClients(ctx, session, userID, pm)
}

// Update traces the "Update" operation of the wrapped clients.Service.
func (tm *tracingMiddleware) Update(ctx context.Context, session authn.Session, cli clients.Client) (clients.Client, error) {
	ctx, span := tm.startSpan(ctx, "svc_update_client", trace.WithAttributes(attribute.String("id", cli.ID)))
	defer span.End()

	return tm.svc.Update(ctx, session, cli)
}

// UpdateTags traces the "UpdateTags" operation of the wrapped clients.Service.
func (tm *tracingMiddleware) UpdateTags(ctx context.Context, session authn.Session, cli clients.Client) (clients.Client, error) {
	ctx, span := tm.startSpan(ctx, "svc_update_client_tags", trace.WithAttributes(
		attribute.String("id", cli.ID),
		attribute.StringSlice("tags", cli.Tags),
	))
	defer span.End()

	return tm.svc.UpdateTags(ctx, session, cli)
}

// UpdateSecret traces the "UpdateSecret" operation of the wrapped clients.Service.
func (tm *tracingMiddleware) UpdateSecret(ctx context.Context, session authn.Session, oldSecret, newSecret string) (clients.Client, error) {
	ctx, span := tm.startSpan(ctx, "svc_update_client_secret")
	defer span.End()

	return tm.svc.UpdateSecret(ctx, session, oldSecret, newSecret)
}

// Enable traces the "Enable" operation of the wrapped clients.Service.
func (tm *tracingMiddleware) Enable(ctx context.Context, session authn.Session, id string) (clients.Client, error) {
	ctx, span := tm.startSpan(ctx, "svc_enable_client", trace.WithAttributes(attribute.String("id", id)))
	defer span.End()

	return tm.svc.Enable(ctx, session, id)
}

// Disable traces the "Disable" operation of the wrapped clients.Service.
func (tm *tracingMiddleware) Disable(ctx context.Context, session authn.Session, id string) (clients.Client, error) {
	ctx, span := tm.startSpan(ctx, "svc_disable_client", trace.WithAttributes(attribute.String("id", id)))
	defer span.End()

	return tm.svc.Disable(ctx, session, id)
}

// Delete traces the "Delete" operation of the wrapped clients.Service.
func (tm *tracingMiddleware) Delete(ctx context.Context, session authn.Session, id string) error {
	ctx, span := tm.startSpan(ctx, "delete_client", trace.WithAttributes(attribute.String("id", id)))
	defer span.End()
	return tm.svc.Delete(ctx, session, id)
}

func (tm *tracingMiddleware) SetParentGroup(ctx context.Context, session authn.Session, parentGroupID string, id string) error {
	ctx, span := tm.startSpan(ctx, "set_parent_group", trace.WithAttributes(
		attribute.String("id", id),
		attribute.String("parent_group_id", parentGroupID),
	))
	defer span.End()
	return tm.svc.SetParentGroup(ctx, session, parentGroupID, id)
}

func (tm *tracingMiddleware) RemoveParentGroup(ctx context.Context, session authn.Session, id string) error {
	ctx, span := tm.startSpan(ctx, "remove_parent_group", trace.WithAttributes(attribute.String("id", id)))
	defer span.End()
	return tm.svc.RemoveParentGroup(ctx, session, id)
}
