// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package authsvc_test

import (
	"fmt"
	"net"
	"os"
	"testing"

	grpcAuthV1 "github.com/absmach/supermq/api/grpc/auth/v1"
	"github.com/absmach/supermq/auth"
	grpcapi "github.com/absmach/supermq/auth/api/grpc/auth"
	"github.com/absmach/supermq/auth/mocks"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	grpchealth "google.golang.org/grpc/health/grpc_health_v1"
)

func TestMain(m *testing.M) {
	svc = new(mocks.Service)
	server := startGRPCServer(svc, port)

	code := m.Run()

	server.GracefulStop()

	os.Exit(code)
}

func startGRPCServer(svc auth.Service, port int) *grpc.Server {
	listener, _ := net.Listen("tcp", fmt.Sprintf(":%d", port))
	server := grpc.NewServer()
	grpcAuthV1.RegisterAuthServiceServer(server, grpcapi.NewAuthServer(svc))

	healthServer := health.NewServer()
	grpchealth.RegisterHealthServer(server, healthServer)
	healthServer.SetServingStatus("auth", grpchealth.HealthCheckResponse_SERVING)

	go func() {
		err := server.Serve(listener)
		assert.Nil(&testing.T{}, err, fmt.Sprintf(`"Unexpected error creating auth server %s"`, err))
	}()

	return server
}
