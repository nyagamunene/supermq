// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package mocks

import (
	"encoding/json"

	"github.com/absmach/magistrala/pkg/messaging"
	twins "github.com/absmach/magistrala/twins"
	"github.com/absmach/senml"
)

var publisher = "twins"

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
