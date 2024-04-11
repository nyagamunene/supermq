// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package lora_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/absmach/magistrala/internal/testsutil"
	"github.com/absmach/magistrala/lora"
	"github.com/absmach/magistrala/lora/mocks"
	"github.com/absmach/magistrala/pkg/errors"
	pubmocks "github.com/absmach/magistrala/pkg/messaging/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const (
	thingID  = "thingID-1"
	chanID   = "chanID-1"
	devEUI   = "devEUI-1"
	appID    = "appID-1"
	thingID2 = "thingID-2"
	chanID2  = "chanID-2"
	devEUI2  = "devEUI-2"
	appID2   = "appID-2"
	msg      = `[{"bn":"msg-base-name","n":"temperature","v": 17},{"n":"humidity","v": 56}]`
)

func newService() (lora.Service, *pubmocks.PubSub, *mocks.RouteMapRepository, *mocks.RouteMapRepository, *mocks.RouteMapRepository) {
	pub := new(pubmocks.PubSub)
	thingsRM := new(mocks.RouteMapRepository)
	channelsRM := new(mocks.RouteMapRepository)
	connsRM := new(mocks.RouteMapRepository)

	return lora.New(pub, thingsRM, channelsRM, connsRM), pub, thingsRM, channelsRM, connsRM
}

func TestPublish(t *testing.T) {
	svc, pub, thingsRM, channelsRM, connsRM := newService()

	repoCall := channelsRM.On("Save", context.Background(), chanID, appID).Return(nil)
	repoCall1 := thingsRM.On("Save", context.Background(), thingID, devEUI).Return(nil)
	repoCall2 := connsRM.On("Save", context.Background(), mock.Anything, mock.Anything).Return(nil)
	repoCall3 := channelsRM.On("Get", context.Background(), chanID).Return(testsutil.GenerateUUID(t), nil)
	repoCall4 := thingsRM.On("Get", context.Background(), thingID).Return(testsutil.GenerateUUID(t), nil)

	err := svc.CreateChannel(context.Background(), chanID, appID)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s\n", err))

	err = svc.CreateThing(context.Background(), thingID, devEUI)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s\n", err))

	err = svc.ConnectThing(context.Background(), chanID, thingID)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s\n", err))
	repoCall.Unset()
	repoCall1.Unset()
	repoCall2.Unset()
	repoCall3.Unset()
	repoCall4.Unset()

	repoCall = channelsRM.On("Save", context.Background(), chanID2, appID2).Return(nil)
	repoCall1 = thingsRM.On("Save", context.Background(), thingID2, devEUI2).Return(nil)
	err = svc.CreateChannel(context.Background(), chanID2, appID2)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s\n", err))

	err = svc.CreateThing(context.Background(), thingID2, devEUI2)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s\n", err))
	repoCall.Unset()
	repoCall1.Unset()

	msgBase64 := base64.StdEncoding.EncodeToString([]byte(msg))

	cases := []struct {
		desc           string
		err            error
		msg            lora.Message
		getThingErr    error
		getChannelErr  error
		connectionsErr error
		publishErr     error
	}{
		{
			desc: "publish message with existing route-map and valid Data",
			err:  nil,
			msg: lora.Message{
				ApplicationID: appID,
				DevEUI:        devEUI,
				Data:          msgBase64,
			},
			getThingErr:    nil,
			getChannelErr:  nil,
			connectionsErr: nil,
			publishErr:     nil,
		},
		{
			desc: "publish message with existing route-map and invalid Data",
			err:  lora.ErrMalformedMessage,
			msg: lora.Message{
				ApplicationID: appID,
				DevEUI:        devEUI,
				Data:          "wrong",
			},
			getThingErr:    nil,
			getChannelErr:  nil,
			connectionsErr: nil,
			publishErr:     errors.New("Failed publishing"),
		},
		{
			desc: "publish message with non existing appID route-map",
			err:  lora.ErrNotFoundApp,
			msg: lora.Message{
				ApplicationID: "wrong",
				DevEUI:        devEUI,
			},
			getChannelErr: lora.ErrNotFoundApp,
		},
		{
			desc: "publish message with non existing devEUI route-map",
			err:  lora.ErrNotFoundDev,
			msg: lora.Message{
				ApplicationID: appID,
				DevEUI:        "wrong",
			},
			getThingErr: lora.ErrNotFoundDev,
		},
		{
			desc: "publish message with non existing connection route-map",
			err:  lora.ErrNotConnected,
			msg: lora.Message{
				ApplicationID: appID2,
				DevEUI:        devEUI2,
			},
			connectionsErr: lora.ErrNotConnected,
		},
	}

	for _, tc := range cases {
		repoCall := thingsRM.On("Get", context.Background(), mock.Anything).Return(tc.msg.DevEUI, tc.getThingErr)
		repoCall1 := channelsRM.On("Get", context.Background(), mock.Anything).Return(tc.msg.ApplicationID, tc.getChannelErr)
		repoCall2 := connsRM.On("Get", context.Background(), mock.Anything).Return(mock.Anything, tc.connectionsErr)
		repoCall3 := pub.On("Publish", context.Background(), mock.Anything, mock.Anything).Return(tc.publishErr)
		err := svc.Publish(context.Background(), &tc.msg)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		repoCall.Unset()
		repoCall1.Unset()
		repoCall2.Unset()
		repoCall3.Unset()
	}
}

func TestConnectThing(t *testing.T) {
	svc, _, thingsRM, channelsRM, connsRM := newService()

	repoCall := channelsRM.On("Save", context.Background(), chanID, appID).Return(nil)
	repoCall1 := thingsRM.On("Save", context.Background(), thingID, devEUI).Return(nil)

	err := svc.CreateChannel(context.Background(), chanID, appID)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s\n", err))

	err = svc.CreateThing(context.Background(), thingID, devEUI)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s\n", err))

	repoCall.Unset()
	repoCall1.Unset()

	cases := []struct {
		desc          string
		err           error
		channelID     string
		thingID       string
		getThingErr   error
		getChannelErr error
	}{
		{
			desc:          "connect thing with valid data",
			err:           nil,
			channelID:     chanID,
			thingID:       thingID,
			getThingErr:   nil,
			getChannelErr: nil,
		},
		{
			desc:        "connect thing with non existing thing",
			err:         lora.ErrNotFoundDev,
			channelID:   chanID,
			thingID:     "wrong",
			getThingErr: lora.ErrNotFoundDev,
		},
		{
			desc:          "connect thing with non existing channel",
			err:           lora.ErrNotFoundApp,
			channelID:     "wrong",
			thingID:       thingID,
			getChannelErr: lora.ErrNotFoundApp,
		},
	}

	for _, tc := range cases {
		repoCall := thingsRM.On("Get", context.Background(), mock.Anything).Return(devEUI, tc.getThingErr)
		repoCall1 := channelsRM.On("Get", context.Background(), mock.Anything).Return(appID, tc.getChannelErr)
		repoCall2 := connsRM.On("Save", context.Background(), mock.Anything, mock.Anything).Return(tc.err)
		err := svc.ConnectThing(context.Background(), tc.channelID, tc.thingID)
		switch err {
		case nil:
			assert.Nil(t, err, fmt.Sprintf("%s: unexpected error %s", tc.desc, err))
		default:
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		}
		repoCall.Unset()
		repoCall1.Unset()
		repoCall2.Unset()
	}
}

func TestDisconnectThing(t *testing.T) {
	svc, _, thingsRM, channelsRM, connsRM := newService()

	repoCall := channelsRM.On("Save", context.Background(), chanID, appID).Return(nil)
	repoCall1 := thingsRM.On("Save", context.Background(), thingID, devEUI).Return(nil)
	repoCall2 := channelsRM.On("Get", context.Background(), chanID).Return(testsutil.GenerateUUID(t), nil)
	repoCall3 := thingsRM.On("Get", context.Background(), thingID).Return(testsutil.GenerateUUID(t), nil)
	repoCall4 := connsRM.On("Save", context.Background(), mock.Anything, mock.Anything).Return(nil)

	err := svc.CreateChannel(context.Background(), chanID, appID)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s\n", err))

	err = svc.CreateThing(context.Background(), thingID, devEUI)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s\n", err))

	err = svc.ConnectThing(context.Background(), chanID, thingID)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s\n", err))
	repoCall.Unset()
	repoCall1.Unset()
	repoCall2.Unset()
	repoCall3.Unset()
	repoCall4.Unset()

	cases := []struct {
		desc          string
		err           error
		channelID     string
		thingID       string
		getThingErr   error
		getChannelErr error
	}{
		{
			desc:          "disconnect thing with valid data",
			err:           nil,
			channelID:     chanID,
			thingID:       thingID,
			getThingErr:   nil,
			getChannelErr: nil,
		},
		{
			desc:        "disconnect thing with non existing thing ID",
			err:         lora.ErrNotFoundDev,
			channelID:   chanID,
			thingID:     "wrong",
			getThingErr: lora.ErrNotFoundDev,
		},
		{
			desc:          "disconnect thing with non existing channel",
			err:           lora.ErrNotFoundApp,
			channelID:     "wrong",
			thingID:       thingID,
			getChannelErr: lora.ErrNotFoundApp,
		},
	}

	for _, tc := range cases {
		repoCall := thingsRM.On("Get", context.Background(), mock.Anything).Return(devEUI, tc.getThingErr)
		repoCall1 := channelsRM.On("Get", context.Background(), mock.Anything).Return(appID, tc.getChannelErr)
		repoCall2 := connsRM.On("Remove", context.Background(), mock.Anything).Return(tc.err)

		err = svc.DisconnectThing(context.Background(), tc.channelID, tc.thingID)
		switch err {
		case nil:
			assert.Nil(t, err, fmt.Sprintf("%s: unexpected error %s", tc.desc, err))
		default:
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		}
		repoCall.Unset()
		repoCall1.Unset()
		repoCall2.Unset()
	}
}
