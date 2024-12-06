// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package keys

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	api "github.com/absmach/supermq/api/http"
	apiutil "github.com/absmach/supermq/api/http/util"
	"github.com/absmach/supermq/auth"
	"github.com/absmach/supermq/pkg/errors"
	"github.com/go-chi/chi/v5"
	kithttp "github.com/go-kit/kit/transport/http"
)

const (
	contentType = "application/json"
	patPrefix   = "pat_"
)

// MakeHandler returns a HTTP handler for API endpoints.
func MakeHandler(svc auth.Service, mux *chi.Mux, logger *slog.Logger) *chi.Mux {
	opts := []kithttp.ServerOption{
		kithttp.ServerErrorEncoder(apiutil.LoggingErrorEncoder(logger, api.EncodeError)),
	}
	mux.Route("/keys", func(r chi.Router) {
		r.Post("/", kithttp.NewServer(
			issueEndpoint(svc),
			decodeIssue,
			api.EncodeResponse,
			opts...,
		).ServeHTTP)

		r.Get("/{id}", kithttp.NewServer(
			(retrieveEndpoint(svc)),
			decodeKeyReq,
			api.EncodeResponse,
			opts...,
		).ServeHTTP)

		r.Delete("/{id}", kithttp.NewServer(
			(revokeEndpoint(svc)),
			decodeKeyReq,
			api.EncodeResponse,
			opts...,
		).ServeHTTP)
	})
	return mux
}

func decodeIssue(_ context.Context, r *http.Request) (interface{}, error) {
	if !strings.Contains(r.Header.Get("Content-Type"), contentType) {
		return nil, apiutil.ErrUnsupportedContentType
	}

	token := apiutil.ExtractBearerToken(r)
	if strings.HasPrefix(token, patPrefix) {
		return nil, apiutil.ErrUnsupportedTokenType
	}

	req := issueKeyReq{token: token}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, errors.Wrap(errors.ErrMalformedEntity, err)
	}

	return req, nil
}

func decodeKeyReq(_ context.Context, r *http.Request) (interface{}, error) {
	token := apiutil.ExtractBearerToken(r)
	if strings.HasPrefix(token, patPrefix) {
		return nil, apiutil.ErrUnsupportedTokenType
	}

	req := keyReq{
		token: token,
		id:    chi.URLParam(r, "id"),
	}
	return req, nil
}
