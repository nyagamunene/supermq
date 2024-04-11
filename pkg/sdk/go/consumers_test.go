// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package sdk_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/absmach/magistrala"
	authmocks "github.com/absmach/magistrala/auth/mocks"
	"github.com/absmach/magistrala/consumers/notifiers"
	httpapi "github.com/absmach/magistrala/consumers/notifiers/api"
	"github.com/absmach/magistrala/consumers/notifiers/mocks"
	"github.com/absmach/magistrala/internal/apiutil"
	"github.com/absmach/magistrala/internal/testsutil"
	mglog "github.com/absmach/magistrala/logger"
	"github.com/absmach/magistrala/pkg/errors"
	svcerr "github.com/absmach/magistrala/pkg/errors/service"
	sdk "github.com/absmach/magistrala/pkg/sdk/go"
	"github.com/absmach/magistrala/pkg/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var (
	sub1 = sdk.Subscription{
		Topic:   "topic",
		Contact: "contact",
	}
	emptySubscription = sdk.Subscription{}
	exampleUser1      = "email1@example.com"
	ID                = testsutil.GenerateUUID(&testing.T{})
)

func setupSubscriptions() (*httptest.Server, *authmocks.AuthClient, *mocks.SubscriptionsRepository) {
	repo := new(mocks.SubscriptionsRepository)
	auth := new(authmocks.AuthClient)
	notifier := new(mocks.Notifier)
	idp := uuid.NewMock()
	from := "exampleFrom"

	svc := notifiers.New(auth, repo, idp, notifier, from)
	logger := mglog.NewMock()
	mux := httpapi.MakeHandler(svc, logger, instanceID)

	return httptest.NewServer(mux), auth, repo
}

func TestCreateSubscription(t *testing.T) {
	ts, auth, repo := setupSubscriptions()
	defer ts.Close()

	sdkConf := sdk.Config{
		UsersURL:        ts.URL,
		MsgContentType:  contentType,
		TLSVerification: false,
	}

	mgsdk := sdk.NewSDK(sdkConf)

	cases := []struct {
		desc         string
		subscription sdk.Subscription
		token        string
		err          errors.SDKError
		empty        bool
		id           string
	}{
		{
			desc:         "create new subscription",
			subscription: sub1,
			token:        exampleUser1,
			err:          nil,
			empty:        false,
			id:           ID,
		},
		{
			desc:         "create new subscription with empty token",
			subscription: sub1,
			token:        "",
			err:          errors.NewSDKErrorWithStatus(errors.Wrap(apiutil.ErrValidation, apiutil.ErrBearerToken), http.StatusUnauthorized),
			empty:        true,
			id:           "",
		},
		{
			desc:         "create new subscription with invalid token",
			subscription: sub1,
			token:        authmocks.InvalidValue,
			err:          errors.NewSDKErrorWithStatus(svcerr.ErrAuthentication, http.StatusUnauthorized),
			empty:        true,
			id:           "",
		},
		{
			desc:         "create new empty subscription",
			subscription: emptySubscription,
			token:        token,
			err:          errors.NewSDKErrorWithStatus(errors.Wrap(apiutil.ErrValidation, apiutil.ErrInvalidTopic), http.StatusBadRequest),
			empty:        true,
			id:           "",
		},
	}

	for _, tc := range cases {
		repoCall := auth.On("Identify", mock.Anything, &magistrala.IdentityReq{Token: tc.token}).Return(&magistrala.IdentityRes{Id: validID}, nil)
		repoCall1 := repo.On("Save", mock.Anything, mock.Anything).Return(tc.id, tc.err)
		loc, err := mgsdk.CreateSubscription(tc.subscription.Topic, tc.subscription.Contact, tc.token)
		assert.Equal(t, tc.err, err, fmt.Sprintf("%s: expected error %s, got %s", tc.desc, tc.err, err))
		assert.Equal(t, tc.empty, loc == "", fmt.Sprintf("%s: expected empty result location, got: %s", tc.desc, loc))
		repoCall.Unset()
		repoCall1.Unset()
	}
}

func TestViewSubscription(t *testing.T) {
	ts, auth, repo := setupSubscriptions()
	defer ts.Close()
	sdkConf := sdk.Config{
		UsersURL:        ts.URL,
		MsgContentType:  contentType,
		TLSVerification: false,
	}

	mgsdk := sdk.NewSDK(sdkConf)
	repoCall := auth.On("Identify", mock.Anything, &magistrala.IdentityReq{Token: exampleUser1}).Return(&magistrala.IdentityRes{Id: validID}, nil)
	repoCall1 := repo.On("Save", mock.Anything, mock.Anything).Return(ID, nil)
	id, err := mgsdk.CreateSubscription("topic", "contact", exampleUser1)
	require.Nil(t, err, fmt.Sprintf("unexpected error during creating subscription: %s", err))
	repoCall.Unset()
	repoCall1.Unset()

	cases := []struct {
		desc     string
		subID    string
		token    string
		err      errors.SDKError
		response sdk.Subscription
	}{
		{
			desc:     "get existing subscription",
			subID:    id,
			token:    exampleUser1,
			err:      nil,
			response: sub1,
		},
		{
			desc:     "get non-existent subscription",
			subID:    "43",
			token:    exampleUser1,
			err:      errors.NewSDKErrorWithStatus(svcerr.ErrNotFound, http.StatusNotFound),
			response: sdk.Subscription{},
		},
		{
			desc:     "get subscription with invalid token",
			subID:    id,
			token:    "",
			err:      errors.NewSDKErrorWithStatus(errors.Wrap(apiutil.ErrValidation, apiutil.ErrBearerToken), http.StatusUnauthorized),
			response: sdk.Subscription{},
		},
	}

	for _, tc := range cases {
		repoCall := auth.On("Identify", mock.Anything, &magistrala.IdentityReq{Token: tc.token}).Return(&magistrala.IdentityRes{Id: validID}, nil)
		repoCall1 := repo.On("Retrieve", mock.Anything, mock.Anything).Return(notifiers.Subscription{Contact: sub1.Contact, Topic: sub1.Topic}, tc.err)
		respSub, err := mgsdk.ViewSubscription(tc.subID, tc.token)
		assert.Equal(t, tc.err, err, fmt.Sprintf("%s: expected error %s, got %s", tc.desc, tc.err, err))
		tc.response.ID = respSub.ID
		tc.response.OwnerID = respSub.OwnerID
		assert.Equal(t, tc.response, respSub, fmt.Sprintf("%s: expected response %s, got %s", tc.desc, tc.response, respSub))
		repoCall.Unset()
		repoCall1.Unset()
	}
}

func TestListSubscription(t *testing.T) {
	ts, auth, repo := setupSubscriptions()
	defer ts.Close()
	sdkConf := sdk.Config{
		UsersURL:        ts.URL,
		MsgContentType:  contentType,
		TLSVerification: false,
	}

	mgsdk := sdk.NewSDK(sdkConf)
	nSubs := 10
	subs := make([]sdk.Subscription, nSubs)
	for i := 0; i < nSubs; i++ {
		repoCall := auth.On("Identify", mock.Anything, &magistrala.IdentityReq{Token: exampleUser1}).Return(&magistrala.IdentityRes{Id: validID}, nil)
		repoCall1 := repo.On("Save", mock.Anything, mock.Anything).Return(ID, nil)
		id, err := mgsdk.CreateSubscription(fmt.Sprintf("topic_%d", i), fmt.Sprintf("contact_%d", i), exampleUser1)
		require.Nil(t, err, fmt.Sprintf("unexpected error during creating subscription: %s", err))
		repoCall.Unset()
		repoCall1.Unset()
		repoCall = auth.On("Identify", mock.Anything, &magistrala.IdentityReq{Token: exampleUser1}).Return(&magistrala.IdentityRes{Id: validID}, nil)
		repoCall1 = repo.On("Retrieve", mock.Anything, mock.Anything).Return(notifiers.Subscription{Contact: sub1.Contact, Topic: sub1.Topic, ID: id}, nil)
		sub, err := mgsdk.ViewSubscription(id, exampleUser1)
		require.Nil(t, err, fmt.Sprintf("unexpected error during getting subscription: %s", err))
		repoCall.Unset()
		repoCall1.Unset()
		subs[i] = sub
	}

	cases := []struct {
		desc     string
		page     sdk.PageMetadata
		token    string
		err      errors.SDKError
		response []sdk.Subscription
		Page     notifiers.Page
	}{
		{
			desc:     "list all subscription",
			token:    exampleUser1,
			page:     sdk.PageMetadata{Offset: 0, Limit: uint64(nSubs)},
			err:      nil,
			response: subs,
			Page: notifiers.Page{
				PageMetadata: notifiers.PageMetadata{
					Offset: 0,
					Limit:  nSubs,
				},
				Subscriptions: GetSubscriptionsSlice(subs, 0, 10),
			},
		},
		{
			desc:     "list subscription with specific topic",
			token:    exampleUser1,
			page:     sdk.PageMetadata{Offset: 0, Limit: uint64(nSubs), Topic: "topic_1"},
			err:      nil,
			response: []sdk.Subscription{subs[1]},
			Page: notifiers.Page{
				PageMetadata: notifiers.PageMetadata{
					Offset: 0,
					Limit:  nSubs,
					Topic:  "topic_1",
				},
				Subscriptions: GetSubscriptionsSlice(subs, 0, 1),
			},
		},
		{
			desc:     "list subscription with specific contact",
			token:    exampleUser1,
			page:     sdk.PageMetadata{Offset: 0, Limit: uint64(nSubs), Contact: "contact_1"},
			err:      nil,
			response: []sdk.Subscription{subs[1]},
			Page: notifiers.Page{
				PageMetadata: notifiers.PageMetadata{
					Offset:  0,
					Limit:   nSubs,
					Contact: "contact_1",
				},
				Subscriptions: GetSubscriptionsSlice(subs, 0, 1),
			},
		},
	}

	for _, tc := range cases {
		repoCall := auth.On("Identify", mock.Anything, &magistrala.IdentityReq{Token: tc.token}).Return(&magistrala.IdentityRes{Id: validID}, nil)
		repoCall1 := repo.On("RetrieveAll", mock.Anything, mock.Anything).Return(tc.Page, tc.err)
		subs, err := mgsdk.ListSubscriptions(tc.page, tc.token)
		assert.Equal(t, tc.err, err, fmt.Sprintf("%s: expected error %s, got %s", tc.desc, tc.err, err))
		assert.Equal(t, tc.response, subs.Subscriptions, fmt.Sprintf("%s: expected response %v, got %v", tc.desc, tc.response, subs.Subscriptions))
		repoCall.Unset()
		repoCall1.Unset()
	}
}

func TestDeleteSubscription(t *testing.T) {
	ts, auth, repo := setupSubscriptions()
	defer ts.Close()
	sdkConf := sdk.Config{
		UsersURL:        ts.URL,
		MsgContentType:  contentType,
		TLSVerification: false,
	}

	mgsdk := sdk.NewSDK(sdkConf)
	repoCall := auth.On("Identify", mock.Anything, &magistrala.IdentityReq{Token: exampleUser1}).Return(&magistrala.IdentityRes{Id: validID}, nil)
	repoCall1 := repo.On("Save", mock.Anything, mock.Anything).Return(ID, nil)
	id, err := mgsdk.CreateSubscription("topic", "contact", exampleUser1)
	require.Nil(t, err, fmt.Sprintf("unexpected error during creating subscription: %s", err))
	repoCall.Unset()
	repoCall1.Unset()

	cases := []struct {
		desc     string
		subID    string
		token    string
		err      errors.SDKError
		response sdk.Subscription
	}{
		{
			desc:     "delete existing subscription",
			subID:    id,
			token:    exampleUser1,
			err:      nil,
			response: sub1,
		},
		{
			desc:     "delete non-existent subscription",
			subID:    "43",
			token:    exampleUser1,
			err:      errors.NewSDKErrorWithStatus(svcerr.ErrNotFound, http.StatusNotFound),
			response: sdk.Subscription{},
		},
		{
			desc:     "delete subscription with invalid token",
			subID:    id,
			token:    "",
			err:      errors.NewSDKErrorWithStatus(errors.Wrap(apiutil.ErrValidation, apiutil.ErrBearerToken), http.StatusUnauthorized),
			response: sdk.Subscription{},
		},
	}

	for _, tc := range cases {
		repoCall := auth.On("Identify", mock.Anything, &magistrala.IdentityReq{Token: tc.token}).Return(&magistrala.IdentityRes{Id: validID}, nil)
		repoCall1 := repo.On("Remove", mock.Anything, mock.Anything).Return(tc.err)
		err := mgsdk.DeleteSubscription(tc.subID, tc.token)
		assert.Equal(t, tc.err, err, fmt.Sprintf("%s: expected error %s, got %s", tc.desc, tc.err, err))
		repoCall.Unset()
		repoCall1.Unset()
	}
}

func GetSubscriptionsSlice(subs []sdk.Subscription, start, end int) []notifiers.Subscription {
	var result []notifiers.Subscription
	for _, sub := range subs {
		result = append(result, notifiers.Subscription{
			ID:      sub.ID,
			OwnerID: sub.OwnerID,
			Contact: sub.Contact,
			Topic:   sub.Topic,
		})
	}
	return result[start:end]
}
