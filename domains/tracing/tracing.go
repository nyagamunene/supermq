// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package tracing

import (
	"context"
	"fmt"
	"strings"

	"github.com/absmach/supermq/domains"
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

var _ domains.Service = (*tracingMiddleware)(nil)

type tracingMiddleware struct {
	tracer trace.Tracer
	svc    domains.Service
	rmTrace.RoleManagerTracing
}

// New returns a new group service with tracing capabilities.
func New(svc domains.Service, tracer trace.Tracer) domains.Service {
	return &tracingMiddleware{tracer, svc, rmTrace.NewRoleManagerTracing("domain", svc, tracer)}
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

func (tm *tracingMiddleware) CreateDomain(ctx context.Context, session authn.Session, d domains.Domain) (domains.Domain, []roles.RoleProvision, error) {
	ctx, span := tm.startSpan(ctx, "create_domain", trace.WithAttributes(
		attribute.String("name", d.Name),
	))
	defer span.End()
	return tm.svc.CreateDomain(ctx, session, d)
}

func (tm *tracingMiddleware) RetrieveDomain(ctx context.Context, session authn.Session, id string) (domains.Domain, error) {
	ctx, span := tm.startSpan(ctx, "view_domain", trace.WithAttributes(
		attribute.String("id", id),
	))
	defer span.End()
	return tm.svc.RetrieveDomain(ctx, session, id)
}

func (tm *tracingMiddleware) UpdateDomain(ctx context.Context, session authn.Session, id string, d domains.DomainReq) (domains.Domain, error) {
	ctx, span := tm.startSpan(ctx, "update_domain", trace.WithAttributes(
		attribute.String("id", id),
	))
	defer span.End()
	return tm.svc.UpdateDomain(ctx, session, id, d)
}

func (tm *tracingMiddleware) EnableDomain(ctx context.Context, session authn.Session, id string) (domains.Domain, error) {
	ctx, span := tm.startSpan(ctx, "enable_domain", trace.WithAttributes(
		attribute.String("id", id),
	))
	defer span.End()
	return tm.svc.EnableDomain(ctx, session, id)
}

func (tm *tracingMiddleware) DisableDomain(ctx context.Context, session authn.Session, id string) (domains.Domain, error) {
	ctx, span := tm.startSpan(ctx, "disable_domain", trace.WithAttributes(
		attribute.String("id", id),
	))
	defer span.End()
	return tm.svc.DisableDomain(ctx, session, id)
}

func (tm *tracingMiddleware) FreezeDomain(ctx context.Context, session authn.Session, id string) (domains.Domain, error) {
	ctx, span := tm.startSpan(ctx, "freeze_domain", trace.WithAttributes(
		attribute.String("id", id),
	))
	defer span.End()
	return tm.svc.FreezeDomain(ctx, session, id)
}

func (tm *tracingMiddleware) ListDomains(ctx context.Context, session authn.Session, p domains.Page) (domains.DomainsPage, error) {
	ctx, span := tm.startSpan(ctx, "list_domains")
	defer span.End()
	return tm.svc.ListDomains(ctx, session, p)
}

func (tm *tracingMiddleware) SendInvitation(ctx context.Context, session authn.Session, invitation domains.Invitation) (err error) {
	ctx, span := tm.startSpan(ctx, "send_invitation", trace.WithAttributes(
		attribute.String("domain_id", invitation.DomainID),
		attribute.String("invitee_user_id", invitation.InviteeUserID),
	))
	defer span.End()

	return tm.svc.SendInvitation(ctx, session, invitation)
}

func (tm *tracingMiddleware) ViewInvitation(ctx context.Context, session authn.Session, inviteeUserID, domain string) (invitation domains.Invitation, err error) {
	ctx, span := tm.startSpan(ctx, "view_invitation", trace.WithAttributes(
		attribute.String("invitee_user_id", inviteeUserID),
		attribute.String("domain_id", domain),
	))
	defer span.End()

	return tm.svc.ViewInvitation(ctx, session, inviteeUserID, domain)
}

func (tm *tracingMiddleware) ListInvitations(ctx context.Context, session authn.Session, pm domains.InvitationPageMeta) (invs domains.InvitationPage, err error) {
	ctx, span := tm.startSpan(ctx, "list_invitations", trace.WithAttributes(
		attribute.Int("limit", int(pm.Limit)),
		attribute.Int("offset", int(pm.Offset)),
		attribute.String("invitee_user_id", pm.InviteeUserID),
		attribute.String("domain_id", pm.DomainID),
		attribute.String("invited_by", pm.InvitedBy),
	))
	defer span.End()

	return tm.svc.ListInvitations(ctx, session, pm)
}

func (tm *tracingMiddleware) AcceptInvitation(ctx context.Context, session authn.Session, domainID string) (err error) {
	ctx, span := tm.startSpan(ctx, "accept_invitation", trace.WithAttributes(
		attribute.String("domain_id", domainID),
	))
	defer span.End()

	return tm.svc.AcceptInvitation(ctx, session, domainID)
}

func (tm *tracingMiddleware) RejectInvitation(ctx context.Context, session authn.Session, domainID string) (err error) {
	ctx, span := tm.startSpan(ctx, "reject_invitation", trace.WithAttributes(
		attribute.String("domain_id", domainID),
	))
	defer span.End()

	return tm.svc.RejectInvitation(ctx, session, domainID)
}

func (tm *tracingMiddleware) DeleteInvitation(ctx context.Context, session authn.Session, inviteeUserID, domainID string) (err error) {
	ctx, span := tm.startSpan(ctx, "delete_invitation", trace.WithAttributes(
		attribute.String("invitee_user_id", inviteeUserID),
		attribute.String("domain_id", domainID),
	))
	defer span.End()

	return tm.svc.DeleteInvitation(ctx, session, inviteeUserID, domainID)
}
