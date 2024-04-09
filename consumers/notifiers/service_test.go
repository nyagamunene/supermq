// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package notifiers_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/absmach/magistrala"
	authmocks "github.com/absmach/magistrala/auth/mocks"
	"github.com/absmach/magistrala/consumers/notifiers"
	"github.com/absmach/magistrala/consumers/notifiers/mocks"
	"github.com/absmach/magistrala/internal/testsutil"
	"github.com/absmach/magistrala/pkg/errors"
	repoerr "github.com/absmach/magistrala/pkg/errors/repository"
	svcerr "github.com/absmach/magistrala/pkg/errors/service"
	"github.com/absmach/magistrala/pkg/messaging"
	"github.com/absmach/magistrala/pkg/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const (
	total        = 100
	exampleUser1 = "token1"
	exampleUser2 = "token2"
	validID      = "d4ebb847-5d0e-4e46-bdd9-b6aceaaa3a22"
)

func newService() (notifiers.Service, *authmocks.AuthClient, *mocks.SubscriptionsRepository) {
	repo := new(mocks.SubscriptionsRepository)
	auth := new(authmocks.AuthClient)
	notifier := new(mocks.Notifier)
	idp := uuid.NewMock()
	from := "exampleFrom"
	return notifiers.New(auth, repo, idp, notifier, from), auth, repo
}

func TestCreateSubscription(t *testing.T) {
	svc, auth, repo := newService()

	cases := []struct {
		desc  string
		token string
		sub   notifiers.Subscription
		id    string
		err   error
	}{
		{
			desc:  "test success",
			token: exampleUser1,
			sub:   notifiers.Subscription{Contact: exampleUser1, Topic: "valid.topic"},
			id:    uuid.Prefix + fmt.Sprintf("%012d", 1),
			err:   nil,
		},
		{
			desc:  "test already existing",
			token: exampleUser1,
			sub:   notifiers.Subscription{Contact: exampleUser1, Topic: "valid.topic"},
			id:    "",
			err:   repoerr.ErrConflict,
		},
		{
			desc:  "test with empty token",
			token: "",
			sub:   notifiers.Subscription{Contact: exampleUser1, Topic: "valid.topic"},
			id:    "",
			err:   svcerr.ErrAuthentication,
		},
	}

	for _, tc := range cases {
		repoCall := auth.On("Identify", mock.Anything, &magistrala.IdentityReq{Token: tc.token}).Return(&magistrala.IdentityRes{Id: testsutil.GenerateUUID(t)}, nil)
		repoCall1 := repo.On("Save", mock.Anything, mock.Anything).Return(tc.id, tc.err)
		id, err := svc.CreateSubscription(context.Background(), tc.token, tc.sub)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		assert.Equal(t, tc.id, id, fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.id, id))
		repoCall.Unset()
		repoCall1.Unset()
	}
}

func TestViewSubscription(t *testing.T) {
	svc, auth, repo := newService()
	sub := notifiers.Subscription{Contact: exampleUser1, Topic: "valid.topic"}
	repoCall := auth.On("Identify", mock.Anything, &magistrala.IdentityReq{Token: exampleUser1}).Return(&magistrala.IdentityRes{Id: validID}, nil)
	repoCall1 := repo.On("Save", mock.Anything, mock.Anything).Return("", nil)
	id, err := svc.CreateSubscription(context.Background(), exampleUser1, sub)
	require.Nil(t, err, "Saving a Subscription must succeed")
	repoCall.Unset()
	repoCall1.Unset()
	sub.ID = id
	sub.OwnerID = validID

	cases := []struct {
		desc  string
		token string
		id    string
		sub   notifiers.Subscription
		err   error
	}{
		{
			desc:  "test success",
			token: exampleUser1,
			id:    id,
			sub:   sub,
			err:   nil,
		},
		{
			desc:  "test not existing",
			token: exampleUser1,
			id:    "not_exist",
			sub:   notifiers.Subscription{},
			err:   svcerr.ErrNotFound,
		},
		{
			desc:  "test with empty token",
			token: "",
			id:    id,
			sub:   notifiers.Subscription{},
			err:   svcerr.ErrAuthentication,
		},
	}

	for _, tc := range cases {
		repoCall := auth.On("Identify", mock.Anything, &magistrala.IdentityReq{Token: tc.token}).Return(&magistrala.IdentityRes{Id: validID}, nil)
		repoCall1 := repo.On("Retrieve", mock.Anything, mock.Anything).Return(tc.sub, tc.err)
		sub, err := svc.ViewSubscription(context.Background(), tc.token, tc.id)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		assert.Equal(t, tc.sub, sub, fmt.Sprintf("%s: expected %v got %v\n", tc.desc, tc.sub, sub))
		repoCall.Unset()
		repoCall1.Unset()
	}
}

func TestListSubscriptions(t *testing.T) {
	svc, auth, repo := newService()
	sub := notifiers.Subscription{Contact: exampleUser1, OwnerID: exampleUser1}
	topic := "topic.subtopic"
	var subs []notifiers.Subscription
	for i := 0; i < total; i++ {
		tmp := sub
		token := exampleUser1
		if i%2 == 0 {
			tmp.Contact = exampleUser2
			tmp.OwnerID = exampleUser2
			token = exampleUser2
		}
		tmp.Topic = fmt.Sprintf("%s.%d", topic, i)
		repoCall := auth.On("Identify", mock.Anything, &magistrala.IdentityReq{Token: token}).Return(&magistrala.IdentityRes{Id: validID}, nil)
		repoCall1 := repo.On("Save", mock.Anything, mock.Anything).Return("", nil)
		id, err := svc.CreateSubscription(context.Background(), token, tmp)
		require.Nil(t, err, "Saving a Subscription must succeed")
		repoCall.Unset()
		repoCall1.Unset()
		tmp.ID = id
		tmp.OwnerID = validID
		subs = append(subs, tmp)
	}

	var offsetSubs []notifiers.Subscription
	for i := 20; i < 40; i += 2 {
		offsetSubs = append(offsetSubs, subs[i])
	}

	cases := []struct {
		desc     string
		token    string
		pageMeta notifiers.PageMetadata
		page     notifiers.Page
		err      error
	}{
		{
			desc:  "test success",
			token: exampleUser1,
			pageMeta: notifiers.PageMetadata{
				Offset: 0,
				Limit:  3,
			},
			err: nil,
			page: notifiers.Page{
				PageMetadata: notifiers.PageMetadata{
					Offset: 0,
					Limit:  3,
				},
				Subscriptions: subs[:3],
				Total:         total,
			},
		},
		{
			desc:  "test not existing",
			token: exampleUser1,
			pageMeta: notifiers.PageMetadata{
				Limit:   10,
				Contact: "empty@example.com",
			},
			page: notifiers.Page{},
			err:  svcerr.ErrNotFound,
		},
		{
			desc:  "test with empty token",
			token: "",
			pageMeta: notifiers.PageMetadata{
				Offset: 2,
				Limit:  12,
				Topic:  "topic.subtopic.13",
			},
			page: notifiers.Page{},
			err:  svcerr.ErrAuthentication,
		},
		{
			desc:  "test with topic",
			token: exampleUser1,
			pageMeta: notifiers.PageMetadata{
				Limit: 10,
				Topic: fmt.Sprintf("%s.%d", topic, 4),
			},
			page: notifiers.Page{
				PageMetadata: notifiers.PageMetadata{
					Limit: 10,
					Topic: fmt.Sprintf("%s.%d", topic, 4),
				},
				Subscriptions: subs[4:5],
				Total:         1,
			},
			err: nil,
		},
		{
			desc:  "test with contact and offset",
			token: exampleUser1,
			pageMeta: notifiers.PageMetadata{
				Offset:  10,
				Limit:   10,
				Contact: exampleUser2,
			},
			page: notifiers.Page{
				PageMetadata: notifiers.PageMetadata{
					Offset:  10,
					Limit:   10,
					Contact: exampleUser2,
				},
				Subscriptions: offsetSubs,
				Total:         uint(total / 2),
			},
			err: nil,
		},
	}

	for _, tc := range cases {
		repoCall := auth.On("Identify", mock.Anything, &magistrala.IdentityReq{Token: tc.token}).Return(&magistrala.IdentityRes{Id: validID}, nil)
		repoCall1 := repo.On("RetrieveAll", mock.Anything, mock.Anything).Return(tc.page, tc.err)
		page, err := svc.ListSubscriptions(context.Background(), tc.token, tc.pageMeta)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		assert.Equal(t, tc.page, page, fmt.Sprintf("%s: got unexpected page\n", tc.desc))
		repoCall.Unset()
		repoCall1.Unset()
	}
}

func TestRemoveSubscription(t *testing.T) {
	svc, auth, repo := newService()
	sub := notifiers.Subscription{Contact: exampleUser1, Topic: "valid.topic"}
	repoCall := auth.On("Identify", mock.Anything, &magistrala.IdentityReq{Token: exampleUser1}).Return(&magistrala.IdentityRes{Id: validID}, nil)
	repoCall1 := repo.On("Save", mock.Anything, mock.Anything).Return("", nil)
	id, err := svc.CreateSubscription(context.Background(), exampleUser1, sub)
	require.Nil(t, err, "Saving a Subscription must succeed")
	repoCall.Unset()
	repoCall1.Unset()
	sub.ID = id
	sub.OwnerID = validID

	cases := []struct {
		desc  string
		token string
		id    string
		err   error
	}{
		{
			desc:  "test success",
			token: exampleUser1,
			id:    id,
			err:   nil,
		},
		{
			desc:  "test not existing",
			token: exampleUser1,
			id:    "not_exist",
			err:   svcerr.ErrNotFound,
		},
		{
			desc:  "test with empty token",
			token: "",
			id:    id,
			err:   svcerr.ErrAuthentication,
		},
	}

	for _, tc := range cases {
		repoCall := auth.On("Identify", mock.Anything, &magistrala.IdentityReq{Token: tc.token}).Return(&magistrala.IdentityRes{Id: validID}, nil)
		repoCall1 := repo.On("Remove", mock.Anything, mock.Anything).Return(tc.err)
		err := svc.RemoveSubscription(context.Background(), tc.token, tc.id)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		repoCall.Unset()
		repoCall1.Unset()
	}
}

func TestConsume(t *testing.T) {
	svc, auth, repo := newService()
	sub := notifiers.Subscription{
		Contact: exampleUser1,
		OwnerID: validID,
		Topic:   "topic.subtopic",
	}
	for i := 0; i < total; i++ {
		tmp := sub
		tmp.Contact = fmt.Sprintf("contact%d@example.com", i)
		if i%2 == 0 {
			tmp.Topic = fmt.Sprintf("%s-2", sub.Topic)
		}
		repoCall := auth.On("Identify", mock.Anything, &magistrala.IdentityReq{Token: exampleUser1}).Return(&magistrala.IdentityRes{Id: validID}, nil)
		repoCall1 := repo.On("Save", mock.Anything, mock.Anything).Return("", nil)
		_, err := svc.CreateSubscription(context.Background(), exampleUser1, tmp)
		require.Nil(t, err, "Saving a Subscription must succeed")
		repoCall.Unset()
		repoCall1.Unset()
	}

	sub.Contact = "invalid@example.com"
	sub.Topic = fmt.Sprintf("%s-2", sub.Topic)
	repoCall := auth.On("Identify", mock.Anything, &magistrala.IdentityReq{Token: exampleUser1}).Return(&magistrala.IdentityRes{Id: validID}, nil)
	repoCall1 := repo.On("Save", mock.Anything, mock.Anything).Return("", nil)
	_, err := svc.CreateSubscription(context.Background(), exampleUser1, sub)
	require.Nil(t, err, "Saving a Subscription must succeed")
	repoCall.Unset()
	repoCall1.Unset()

	msg := messaging.Message{
		Channel:  "topic",
		Subtopic: "subtopic",
	}
	errMsg := messaging.Message{
		Channel:  "topic",
		Subtopic: "subtopic-2",
	}

	cases := []struct {
		desc string
		msg  *messaging.Message
		err  error
	}{
		{
			desc: "test success",
			msg:  &msg,
			err:  nil,
		},
		{
			desc: "test fail",
			msg:  &errMsg,
			err:  notifiers.ErrNotify,
		},
	}

	for _, tc := range cases {
		repoCall := repo.On("RetrieveAll", mock.Anything, mock.Anything).Return(notifiers.Page{}, tc.err)
		err := svc.ConsumeBlocking(context.TODO(), tc.msg)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		repoCall.Unset()
	}
}
