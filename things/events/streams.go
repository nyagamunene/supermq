// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package events

import (
	"context"

	"github.com/absmach/magistrala/pkg/authn"
	"github.com/absmach/magistrala/pkg/events"
	"github.com/absmach/magistrala/pkg/events/store"
	rmEvents "github.com/absmach/magistrala/pkg/roles/rolemanager/events"
	"github.com/absmach/magistrala/things"
)

const streamID = "magistrala.things"

var _ things.Service = (*eventStore)(nil)

type eventStore struct {
	events.Publisher
	svc things.Service
	rmEvents.RoleManagerEventStore
}

// NewEventStoreMiddleware returns wrapper around things service that sends
// events to event store.
func NewEventStoreMiddleware(ctx context.Context, svc things.Service, url string) (things.Service, error) {
	publisher, err := store.NewPublisher(ctx, url, streamID)
	if err != nil {
		return nil, err
	}
	res := rmEvents.NewRoleManagerEventStore("things", svc, publisher)

	return &eventStore{
		svc:                   svc,
		Publisher:             publisher,
		RoleManagerEventStore: res,
	}, nil
}

func (es *eventStore) CreateClients(ctx context.Context, session authn.Session, thing ...things.Client) ([]things.Client, error) {
	sths, err := es.svc.CreateClients(ctx, session, thing...)
	if err != nil {
		return sths, err
	}

	for _, th := range sths {
		th.Domain = session.DomainID
		event := createClientEvent{
			session.DomainID,
			th,
		}
		if err := es.Publish(ctx, event); err != nil {
			return sths, err
		}
	}

	return sths, nil
}

func (es *eventStore) Update(ctx context.Context, session authn.Session, thing things.Client) (things.Client, error) {
	cli, err := es.svc.Update(ctx, session, thing)
	if err != nil {
		return cli, err
	}

	return es.update(ctx, "", session, cli)
}

func (es *eventStore) UpdateTags(ctx context.Context, session authn.Session, thing things.Client) (things.Client, error) {
	cli, err := es.svc.UpdateTags(ctx, session, thing)
	if err != nil {
		return cli, err
	}

	return es.update(ctx, "tags", session, cli)
}

func (es *eventStore) UpdateSecret(ctx context.Context, session authn.Session, id, key string) (things.Client, error) {
	cli, err := es.svc.UpdateSecret(ctx, session, id, key)
	if err != nil {
		return cli, err
	}

	return es.update(ctx, "secret", session, cli)
}

func (es *eventStore) update(ctx context.Context, operation string, session authn.Session, thing things.Client) (things.Client, error) {
	event := updateClientEvent{
		Client:    thing,
		operation: operation,
		domainID:  session.DomainID,
	}

	if err := es.Publish(ctx, event); err != nil {
		return thing, err
	}

	return thing, nil
}

func (es *eventStore) View(ctx context.Context, session authn.Session, id string) (things.Client, error) {
	thi, err := es.svc.View(ctx, session, id)
	if err != nil {
		return thi, err
	}
	event := viewClientEvent{
		Client:   thi,
		domainID: session.DomainID,
	}
	if err := es.Publish(ctx, event); err != nil {
		return thi, err
	}

	return thi, nil
}

func (es *eventStore) ListClients(ctx context.Context, session authn.Session, reqUserID string, pm things.Page) (things.ClientsPage, error) {
	cp, err := es.svc.ListClients(ctx, session, reqUserID, pm)
	if err != nil {
		return cp, err
	}
	event := listClientEvent{
		domainID:  session.DomainID,
		reqUserID: reqUserID,
		Page:      pm,
	}
	if err := es.Publish(ctx, event); err != nil {
		return cp, err
	}

	return cp, nil
}

func (es *eventStore) Enable(ctx context.Context, session authn.Session, id string) (things.Client, error) {
	thi, err := es.svc.Enable(ctx, session, id)
	if err != nil {
		return thi, err
	}

	return es.changeStatus(ctx, session, thi)
}

func (es *eventStore) Disable(ctx context.Context, session authn.Session, id string) (things.Client, error) {
	thi, err := es.svc.Disable(ctx, session, id)
	if err != nil {
		return thi, err
	}

	return es.changeStatus(ctx, session, thi)
}

func (es *eventStore) changeStatus(ctx context.Context, session authn.Session, thi things.Client) (things.Client, error) {
	event := changeStatusClientEvent{
		id:        thi.ID,
		updatedAt: thi.UpdatedAt,
		updatedBy: thi.UpdatedBy,
		status:    thi.Status.String(),
		domainID:  session.DomainID,
	}
	if err := es.Publish(ctx, event); err != nil {
		return thi, err
	}

	return thi, nil
}

func (es *eventStore) Delete(ctx context.Context, session authn.Session, id string) error {
	if err := es.svc.Delete(ctx, session, id); err != nil {
		return err
	}

	event := removeClientEvent{id: id, domainID: session.DomainID}

	if err := es.Publish(ctx, event); err != nil {
		return err
	}

	return nil
}

func (es *eventStore) SetParentGroup(ctx context.Context, session authn.Session, parentGroupID string, id string) (err error) {
	if err := es.svc.SetParentGroup(ctx, session, parentGroupID, id); err != nil {
		return err
	}

	event := setParentGroupEvent{parentGroupID: parentGroupID, id: id, domainID: session.DomainID}

	if err := es.Publish(ctx, event); err != nil {
		return err
	}

	return nil
}

func (es *eventStore) RemoveParentGroup(ctx context.Context, session authn.Session, id string) (err error) {
	if err := es.svc.RemoveParentGroup(ctx, session, id); err != nil {
		return err
	}

	event := removeParentGroupEvent{id: id, domainID: session.DomainID}

	if err := es.Publish(ctx, event); err != nil {
		return err
	}

	return nil
}
