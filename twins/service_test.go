// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package twins_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/absmach/magistrala"
	authmocks "github.com/absmach/magistrala/auth/mocks"
	"github.com/absmach/magistrala/internal/testsutil"
	mglog "github.com/absmach/magistrala/logger"
	"github.com/absmach/magistrala/pkg/errors"
	svcerr "github.com/absmach/magistrala/pkg/errors/service"
	"github.com/absmach/magistrala/pkg/messaging"
	"github.com/absmach/magistrala/pkg/uuid"
	"github.com/absmach/magistrala/twins"
	"github.com/absmach/magistrala/twins/mocks"
	"github.com/absmach/senml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const (
	twinName  = "name"
	wrongID   = ""
	token     = "token"
	email     = "user@example.com"
	numRecs   = 100
	retained  = "saved"
	publisher = "twins"
)

var (
	subtopics = []string{"engine", "chassis", "wheel_2"}
	channels  = []string{"01ec3c3e-0e66-4e69-9751-a0545b44e08f", "48061e4f-7c23-4f5c-9012-0f9b7cd9d18d", "5b2180e4-e96b-4469-9dc1-b6745078d0b6"}
	id        = 0
)

func NewService() (twins.Service, *authmocks.AuthClient, *mocks.TwinRepository, *mocks.TwinCache, *mocks.StateRepository) {
	auth := new(authmocks.AuthClient)
	twinsRepo := new(mocks.TwinRepository)
	twinCache := new(mocks.TwinCache)
	statesRepo := new(mocks.StateRepository)
	idProvider := uuid.NewMock()
	subs := map[string]string{"chanID": "chanID"}
	broker := mocks.NewBroker(subs)

	return twins.New(broker, auth, twinsRepo, twinCache, statesRepo, idProvider, "chanID", mglog.NewMock()), auth, twinsRepo, twinCache, statesRepo
}

func TestAddTwin(t *testing.T) {
	svc, auth, twinRepo, twinCache, _ := NewService()
	twin := twins.Twin{}
	def := twins.Definition{}

	cases := []struct {
		desc  string
		twin  twins.Twin
		token string
		err   error
	}{
		{
			desc:  "add new twin",
			twin:  twin,
			token: token,
			err:   nil,
		},
		{
			desc:  "add twin with wrong credentials",
			twin:  twin,
			token: authmocks.InvalidValue,
			err:   svcerr.ErrAuthentication,
		},
	}

	for _, tc := range cases {
		repoCall := auth.On("Identify", mock.Anything, &magistrala.IdentityReq{Token: tc.token}).Return(&magistrala.IdentityRes{Id: testsutil.GenerateUUID(t)}, nil)
		repoCall1 := twinRepo.On("Save", context.Background(), mock.Anything).Return(retained, tc.err)
		repoCall2 := twinCache.On("Save", context.Background(), mock.Anything).Return(tc.err)
		_, err := svc.AddTwin(context.Background(), tc.token, tc.twin, def)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		repoCall.Unset()
		repoCall1.Unset()
		repoCall2.Unset()
	}
}

func TestUpdateTwin(t *testing.T) {
	svc, auth, twinRepo, twinCache, _ := NewService()
	twin := twins.Twin{}
	other := twins.Twin{}
	def := twins.Definition{}

	other.ID = wrongID
	repoCall := auth.On("Identify", mock.Anything, &magistrala.IdentityReq{Token: token}).Return(&magistrala.IdentityRes{Id: testsutil.GenerateUUID(t)}, nil)
	repoCall1 := twinRepo.On("Save", context.Background(), mock.Anything).Return(retained, nil)
	repoCall2 := twinCache.On("Save", context.Background(), mock.Anything).Return(nil)
	saved, err := svc.AddTwin(context.Background(), token, twin, def)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s\n", err))
	repoCall.Unset()
	repoCall1.Unset()
	repoCall2.Unset()

	saved.Name = twinName

	cases := []struct {
		desc  string
		twin  twins.Twin
		token string
		err   error
	}{
		{
			desc:  "update existing twin",
			twin:  saved,
			token: token,
			err:   nil,
		},
		{
			desc:  "update twin with wrong credentials",
			twin:  saved,
			token: authmocks.InvalidValue,
			err:   svcerr.ErrAuthentication,
		},
		{
			desc:  "update non-existing twin",
			twin:  other,
			token: token,
			err:   svcerr.ErrNotFound,
		},
	}

	for _, tc := range cases {
		repoCall := auth.On("Identify", mock.Anything, &magistrala.IdentityReq{Token: tc.token}).Return(&magistrala.IdentityRes{Id: testsutil.GenerateUUID(t)}, nil)
		repoCall1 := twinRepo.On("RetrieveByID", context.Background(), tc.twin.ID).Return(tc.twin, tc.err)
		repoCall2 := twinRepo.On("Update", context.Background(), mock.Anything).Return(nil)
		repoCall3 := twinCache.On("Update", context.Background(), mock.Anything).Return(nil)
		err := svc.UpdateTwin(context.Background(), tc.token, tc.twin, def)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		repoCall.Unset()
		repoCall1.Unset()
		repoCall2.Unset()
		repoCall3.Unset()
	}
}

func TestViewTwin(t *testing.T) {
	svc, auth, twinRepo, twinCache, _ := NewService()
	twin := twins.Twin{}
	def := twins.Definition{}
	repoCall := auth.On("Identify", mock.Anything, &magistrala.IdentityReq{Token: token}).Return(&magistrala.IdentityRes{Id: testsutil.GenerateUUID(t)}, nil)
	repoCall1 := twinRepo.On("Save", context.Background(), mock.Anything).Return(retained, nil)
	repoCall2 := twinCache.On("Save", context.Background(), mock.Anything).Return(nil)
	saved, err := svc.AddTwin(context.Background(), token, twin, def)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s\n", err))
	repoCall.Unset()
	repoCall1.Unset()
	repoCall2.Unset()

	cases := []struct {
		desc  string
		id    string
		token string
		err   error
	}{
		{
			desc:  "view existing twin",
			id:    saved.ID,
			token: token,
			err:   nil,
		},
		{
			desc:  "view twin with wrong credentials",
			id:    saved.ID,
			token: authmocks.InvalidValue,
			err:   svcerr.ErrAuthentication,
		},
		{
			desc:  "view non-existing twin",
			id:    wrongID,
			token: token,
			err:   svcerr.ErrNotFound,
		},
	}

	for _, tc := range cases {
		repoCall := auth.On("Identify", mock.Anything, &magistrala.IdentityReq{Token: tc.token}).Return(&magistrala.IdentityRes{Id: testsutil.GenerateUUID(t)}, nil)
		repoCall1 := twinRepo.On("RetrieveByID", context.Background(), tc.id).Return(twins.Twin{}, tc.err)
		_, err := svc.ViewTwin(context.Background(), tc.token, tc.id)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		repoCall.Unset()
		repoCall1.Unset()
	}
}

func TestListTwins(t *testing.T) {
	svc, auth, twinRepo, twinCache, _ := NewService()
	twin := twins.Twin{Name: twinName, Owner: email}
	def := twins.Definition{}
	m := make(map[string]interface{})
	m["serial"] = "123456"
	twin.Metadata = m

	n := uint64(10)
	for i := uint64(0); i < n; i++ {
		repoCall := auth.On("Identify", mock.Anything, &magistrala.IdentityReq{Token: token}).Return(&magistrala.IdentityRes{Id: testsutil.GenerateUUID(t)}, nil)
		repoCall1 := twinRepo.On("Save", context.Background(), mock.Anything).Return(retained, nil)
		repoCall2 := twinCache.On("Save", context.Background(), mock.Anything).Return(nil)
		_, err := svc.AddTwin(context.Background(), token, twin, def)
		require.Nil(t, err, fmt.Sprintf("unexpected error: %s\n", err))
		repoCall.Unset()
		repoCall1.Unset()
		repoCall2.Unset()
	}

	cases := []struct {
		desc     string
		token    string
		offset   uint64
		limit    uint64
		size     uint64
		metadata map[string]interface{}
		err      error
	}{
		{
			desc:   "list all twins",
			token:  token,
			offset: 0,
			limit:  n,
			size:   n,
			err:    nil,
		},
		{
			desc:   "list with zero limit",
			token:  token,
			limit:  0,
			offset: 0,
			size:   0,
			err:    nil,
		},
		{
			desc:   "list with offset and limit",
			token:  token,
			offset: 8,
			limit:  5,
			size:   2,
			err:    nil,
		},
		{
			desc:   "list with wrong credentials",
			token:  authmocks.InvalidValue,
			limit:  0,
			offset: n,
			err:    svcerr.ErrAuthentication,
		},
	}

	for _, tc := range cases {
		repoCall := auth.On("Identify", mock.Anything, &magistrala.IdentityReq{Token: tc.token}).Return(&magistrala.IdentityRes{Id: testsutil.GenerateUUID(t)}, nil)
		repoCall1 := twinRepo.On("RetrieveAll", context.Background(), mock.Anything, tc.offset, tc.limit, twinName, mock.Anything).Return(twins.Page{}, tc.err)
		_, err := svc.ListTwins(context.Background(), tc.token, tc.offset, tc.limit, twinName, tc.metadata)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		repoCall.Unset()
		repoCall1.Unset()
	}
}

func TestRemoveTwin(t *testing.T) {
	svc, auth, twinRepo, twinCache, _ := NewService()
	twin := twins.Twin{}
	def := twins.Definition{}
	repoCall := auth.On("Identify", mock.Anything, &magistrala.IdentityReq{Token: token}).Return(&magistrala.IdentityRes{Id: testsutil.GenerateUUID(t)}, nil)
	repoCall1 := twinRepo.On("Save", context.Background(), mock.Anything).Return(retained, nil)
	repoCall2 := twinCache.On("Save", context.Background(), mock.Anything).Return(nil)
	saved, err := svc.AddTwin(context.Background(), token, twin, def)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s\n", err))
	repoCall.Unset()
	repoCall1.Unset()
	repoCall2.Unset()

	cases := []struct {
		desc  string
		id    string
		token string
		err   error
	}{
		{
			desc:  "remove twin with wrong credentials",
			id:    saved.ID,
			token: authmocks.InvalidValue,
			err:   svcerr.ErrAuthentication,
		},
		{
			desc:  "remove existing twin",
			id:    saved.ID,
			token: token,
			err:   nil,
		},
		{
			desc:  "remove removed twin",
			id:    saved.ID,
			token: token,
			err:   nil,
		},
		{
			desc:  "remove non-existing twin",
			id:    wrongID,
			token: token,
			err:   nil,
		},
	}

	for _, tc := range cases {
		repoCall := auth.On("Identify", mock.Anything, &magistrala.IdentityReq{Token: tc.token}).Return(&magistrala.IdentityRes{Id: testsutil.GenerateUUID(t)}, nil)
		repoCall1 := twinRepo.On("Remove", context.Background(), tc.id).Return(tc.err)
		repoCall2 := twinCache.On("Remove", context.Background(), tc.id).Return(tc.err)
		err := svc.RemoveTwin(context.Background(), tc.token, tc.id)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		repoCall.Unset()
		repoCall1.Unset()
		repoCall2.Unset()
	}
}

func TestSaveStates(t *testing.T) {
	svc, auth, twinRepo, twinCache, stateRepo := NewService()

	twin := twins.Twin{Owner: email}
	def := CreateDefinition(channels[0:2], subtopics[0:2])
	attr := def.Attributes[0]
	attrSansTwin := CreateDefinition(channels[2:3], subtopics[2:3]).Attributes[0]
	repoCall := auth.On("Identify", mock.Anything, &magistrala.IdentityReq{Token: token}).Return(&magistrala.IdentityRes{Id: testsutil.GenerateUUID(t)}, nil)
	repoCall1 := twinRepo.On("Save", context.Background(), mock.Anything).Return(retained, nil)
	repoCall2 := twinCache.On("Save", context.Background(), mock.Anything).Return(nil)
	tw, err := svc.AddTwin(context.Background(), token, twin, def)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))
	repoCall.Unset()
	repoCall1.Unset()
	repoCall2.Unset()

	defWildcard := CreateDefinition(channels[0:2], []string{twins.SubtopicWildcard, twins.SubtopicWildcard})
	repoCall = auth.On("Identify", mock.Anything, &magistrala.IdentityReq{Token: token}).Return(&magistrala.IdentityRes{Id: testsutil.GenerateUUID(t)}, nil)
	repoCall1 = twinRepo.On("Save", context.Background(), mock.Anything).Return(retained, nil)
	repoCall2 = twinCache.On("Save", context.Background(), mock.Anything).Return(nil)
	twWildcard, err := svc.AddTwin(context.Background(), token, twin, defWildcard)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))
	repoCall.Unset()
	repoCall1.Unset()
	repoCall2.Unset()

	recs := make([]senml.Record, numRecs)
	CreateSenML(recs)

	var ttlAdded uint64

	cases := []struct {
		desc   string
		recs   []senml.Record
		attr   twins.Attribute
		size   uint64
		err    error
		String []string
		page   twins.StatesPage
	}{
		{
			desc: "add 100 states",
			recs: recs,
			attr: attr,
			size: numRecs,
			err:  nil,
			page: twins.StatesPage{
				PageMetadata: twins.PageMetadata{
					Total: numRecs,
				},
			},
		},
		{
			desc: "add 20 states",
			recs: recs[10:30],
			attr: attr,
			size: 20,
			err:  nil,
			page: twins.StatesPage{
				PageMetadata: twins.PageMetadata{
					Total: numRecs + 20,
				},
			},
		},
		{
			desc: "add 20 states for atttribute without twin",
			recs: recs[30:50],
			size: 0,
			attr: attrSansTwin,
			err:  svcerr.ErrNotFound,
			page: twins.StatesPage{
				PageMetadata: twins.PageMetadata{
					Total: numRecs + 20,
				},
			},
		},
		{
			desc: "use empty senml record",
			recs: []senml.Record{},
			attr: attr,
			size: 0,
			err:  nil,
			page: twins.StatesPage{
				PageMetadata: twins.PageMetadata{
					Total: numRecs + 20,
				},
			},
		},
	}

	for _, tc := range cases {
		repoCall := auth.On("Identify", mock.Anything, &magistrala.IdentityReq{Token: token}).Return(&magistrala.IdentityRes{Id: testsutil.GenerateUUID(t)}, nil)
		message, err := CreateMessage(tc.attr, tc.recs)
		assert.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

		repoCall1 := twinRepo.On("RetrieveByAttribute", context.Background(), mock.Anything, mock.Anything).Return(tc.String, nil)
		repoCall2 := twinRepo.On("SaveIDs", context.Background(), mock.Anything, mock.Anything, mock.Anything).Return(tc.err)
		repoCall3 := twinCache.On("IDs", context.Background(), mock.Anything, mock.Anything).Return(tc.String, nil)
		err = svc.SaveStates(context.Background(), message)
		assert.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

		ttlAdded += tc.size
		repoCall4 := stateRepo.On("RetrieveAll", context.TODO(), mock.Anything, mock.Anything, tw.ID).Return(tc.page, nil)
		page, err := svc.ListStates(context.TODO(), token, 0, 10, tw.ID)
		assert.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))
		assert.Equal(t, ttlAdded, page.Total, fmt.Sprintf("%s: expected %d total got %d total\n", tc.desc, ttlAdded, page.Total))

		repoCall5 := stateRepo.On("RetrieveAll", context.TODO(), mock.Anything, mock.Anything, twWildcard.ID).Return(tc.page, nil)
		page, err = svc.ListStates(context.TODO(), token, 0, 10, twWildcard.ID)
		assert.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))
		assert.Equal(t, ttlAdded, page.Total, fmt.Sprintf("%s: expected %d total got %d total\n", tc.desc, ttlAdded, page.Total))
		repoCall.Unset()
		repoCall1.Unset()
		repoCall2.Unset()
		repoCall3.Unset()
		repoCall4.Unset()
		repoCall5.Unset()
	}
}

func TestListStates(t *testing.T) {
	svc, auth, twinRepo, twinCache, stateRepo := NewService()

	twin := twins.Twin{Owner: email}
	def := CreateDefinition(channels[0:2], subtopics[0:2])
	attr := def.Attributes[0]
	repoCall := auth.On("Identify", mock.Anything, &magistrala.IdentityReq{Token: token}).Return(&magistrala.IdentityRes{Id: testsutil.GenerateUUID(t)}, nil)
	repoCall1 := twinRepo.On("Save", context.Background(), mock.Anything).Return(retained, nil)
	repoCall2 := twinCache.On("Save", context.Background(), mock.Anything).Return(nil)
	tw, err := svc.AddTwin(context.Background(), token, twin, def)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))
	repoCall.Unset()
	repoCall1.Unset()
	repoCall2.Unset()

	repoCall = auth.On("Identify", mock.Anything, &magistrala.IdentityReq{Token: token}).Return(&magistrala.IdentityRes{Id: testsutil.GenerateUUID(t)}, nil)
	repoCall1 = twinRepo.On("Save", context.Background(), mock.Anything).Return(retained, nil)
	repoCall2 = twinCache.On("Save", context.Background(), mock.Anything).Return(nil)
	tw2, err := svc.AddTwin(context.Background(), token,
		twins.Twin{Owner: email},
		CreateDefinition(channels[2:3], subtopics[2:3]))
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))
	repoCall.Unset()
	repoCall1.Unset()
	repoCall2.Unset()

	recs := make([]senml.Record, numRecs)
	CreateSenML(recs)
	message, err := CreateMessage(attr, recs)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))
	var testString []string
	repoCall = auth.On("Identify", mock.Anything, &magistrala.IdentityReq{Token: token}).Return(&magistrala.IdentityRes{Id: testsutil.GenerateUUID(t)}, nil)
	repoCall1 = twinCache.On("IDs", context.Background(), mock.Anything, mock.Anything).Return(testString, nil)
	repoCall2 = twinRepo.On("RetrieveByAttribute", context.Background(), mock.Anything, mock.Anything).Return(testString, nil)
	repoCall3 := twinRepo.On("SaveIDs", context.Background(), mock.Anything, mock.Anything, mock.Anything).Return(nil)
	err = svc.SaveStates(context.Background(), message)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))
	repoCall.Unset()
	repoCall1.Unset()
	repoCall2.Unset()
	repoCall3.Unset()

	cases := []struct {
		desc   string
		id     string
		token  string
		offset uint64
		limit  uint64
		size   int
		err    error
		page   twins.StatesPage
	}{
		{
			desc:   "get a list of first 10 states",
			id:     tw.ID,
			token:  token,
			offset: 0,
			limit:  10,
			size:   10,
			err:    nil,
			page: twins.StatesPage{
				States: genStates(10),
			},
		},
		{
			desc:   "get a list of last 10 states",
			id:     tw.ID,
			token:  token,
			offset: numRecs - 10,
			limit:  numRecs,
			size:   10,
			err:    nil,
			page: twins.StatesPage{
				States: genStates(10),
			},
		},
		{
			desc:   "get a list of last 10 states with limit > numRecs",
			id:     tw.ID,
			token:  token,
			offset: numRecs - 10,
			limit:  numRecs + 10,
			size:   10,
			err:    nil,
			page: twins.StatesPage{
				States: genStates(10),
			},
		},
		{
			desc:   "get a list of first 10 states with offset == numRecs",
			id:     tw.ID,
			token:  token,
			offset: numRecs,
			limit:  numRecs + 10,
			size:   0,
			err:    nil,
		},
		{
			desc:   "get a list with wrong user token",
			id:     tw.ID,
			token:  authmocks.InvalidValue,
			offset: 0,
			limit:  10,
			size:   0,
			err:    svcerr.ErrAuthentication,
		},
		{
			desc:   "get a list with id of non-existent twin",
			id:     "1234567890",
			token:  token,
			offset: 0,
			limit:  10,
			size:   0,
			err:    nil,
		},
		{
			desc:   "get a list with id of existing twin without states ",
			id:     tw2.ID,
			token:  token,
			offset: 0,
			limit:  10,
			size:   0,
			err:    nil,
		},
	}

	for _, tc := range cases {
		repoCall := auth.On("Identify", mock.Anything, &magistrala.IdentityReq{Token: tc.token}).Return(&magistrala.IdentityRes{Id: testsutil.GenerateUUID(t)}, nil)
		repoCall1 := stateRepo.On("RetrieveAll", context.TODO(), mock.Anything, mock.Anything, tc.id).Return(tc.page, nil)
		page, err := svc.ListStates(context.TODO(), tc.token, tc.offset, tc.limit, tc.id)
		assert.Equal(t, tc.err, err, fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		assert.Equal(t, tc.size, len(page.States), fmt.Sprintf("%s: expected %d total got %d total\n", tc.desc, tc.size, len(page.States)))
		repoCall.Unset()
		repoCall1.Unset()
	}
}

// CreateDefinition creates twin definition.
func CreateDefinition(channels, subtopics []string) twins.Definition {
	var def twins.Definition
	for i := range channels {
		attr := twins.Attribute{
			Channel:      channels[i],
			Subtopic:     subtopics[i],
			PersistState: true,
		}
		def.Attributes = append(def.Attributes, attr)
	}
	return def
}

// CreateTwin creates twin.
func CreateTwin(channels, subtopics []string) twins.Twin {
	id++
	return twins.Twin{
		ID:          strconv.Itoa(id),
		Definitions: []twins.Definition{CreateDefinition(channels, subtopics)},
	}
}

// CreateSenML creates SenML record array.
func CreateSenML(recs []senml.Record) {
	for i, rec := range recs {
		rec.BaseTime = float64(time.Now().Unix())
		rec.Time = float64(i)
		rec.Value = nil
	}
}

// CreateMessage creates Magistrala message using SenML record array.
func CreateMessage(attr twins.Attribute, recs []senml.Record) (*messaging.Message, error) {
	mRecs, err := json.Marshal(recs)
	if err != nil {
		return nil, err
	}
	return &messaging.Message{
		Channel:   attr.Channel,
		Subtopic:  attr.Subtopic,
		Payload:   mRecs,
		Publisher: publisher,
	}, nil
}

func genStates(length int) []twins.State {
    states := make([]twins.State, length)
    for i := range states {
        states[i] = twins.State{} // Replace with the actual state you want to add
    }
    return states
}