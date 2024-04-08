// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package lora_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/absmach/magistrala/lora"
	"github.com/absmach/magistrala/lora/mocks"
	"github.com/absmach/magistrala/pkg/errors"
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

func newService() (lora.Service, *mocks.RouteMapRepository, *mocks.RouteMapRepository, *mocks.RouteMapRepository) {
	pub := mocks.NewPublisher()
	thingsRM := new(mocks.RouteMapRepository)
	channelsRM := new(mocks.RouteMapRepository)
	connsRM := new(mocks.RouteMapRepository)

	return lora.New(pub, thingsRM, channelsRM, connsRM), thingsRM, channelsRM, connsRM
}

func TestPublish(t *testing.T) {
	svc, thingsRM, channelsRM, connsRM := newService()

	repoCall := channelsRM.On("Save", context.Background(), mock.Anything, mock.Anything).Return(nil)
	repoCall1 := thingsRM.On("Save", context.Background(), mock.Anything, mock.Anything).Return(nil)
	repoCall3 := channelsRM.On("Get", context.Background(), mock.Anything).Return("", nil)
	repoCall4 := thingsRM.On("Get", context.Background(), mock.Anything).Return("", nil)
	repoCall5 := connsRM.On("Save", context.Background(), mock.Anything, mock.Anything).Return(nil)

	err := svc.CreateChannel(context.Background(), chanID, appID)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s\n", err))

	err = svc.CreateThing(context.Background(), thingID, devEUI)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s\n", err))

	err = svc.ConnectThing(context.Background(), chanID, thingID)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s\n", err))

	err = svc.CreateChannel(context.Background(), chanID2, appID2)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s\n", err))

	err = svc.CreateThing(context.Background(), thingID2, devEUI2)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s\n", err))

	repoCall.Unset()
	repoCall1.Unset()
	repoCall3.Unset()
	repoCall4.Unset()
	repoCall5.Unset()

	msgBase64 := base64.StdEncoding.EncodeToString([]byte(msg))

	cases := []struct {
		desc           string
		err            error
		msg            lora.Message
		getThingErr    error
		getChannelErr  error
		connectionsErr error
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
		repoCall := thingsRM.On("Get", context.Background(), tc.msg.DevEUI).Return("", tc.getThingErr)
		repoCall1 := channelsRM.On("Get", context.Background(), tc.msg.ApplicationID).Return("", tc.getChannelErr)
		repoCall2 := connsRM.On("Get", context.Background(), mock.Anything).Return("", tc.connectionsErr)
		err := svc.Publish(context.Background(), &tc.msg)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		repoCall.Unset()
		repoCall1.Unset()
		repoCall2.Unset()
	}
}
