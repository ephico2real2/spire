package api

import (
	"context"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	debugv1 "github.com/spiffe/spire/pkg/agent/api/debug/v1"
	delegatedidentityv1 "github.com/spiffe/spire/pkg/agent/api/delegatedidentity/v1"
	loggerv1 "github.com/spiffe/spire/pkg/agent/api/logger/v1"
	"github.com/spiffe/spire/pkg/agent/endpoints"
	"github.com/spiffe/spire/pkg/common/api/middleware"
	"github.com/spiffe/spire/pkg/common/peertracker"
	"github.com/spiffe/spire/pkg/common/telemetry"

	"google.golang.org/grpc"
)

type Server interface {
	ListenAndServe(ctx context.Context) error
}

type Endpoints struct {
	c        *Config
	listener *peertracker.ListenerFactory
}

func (e *Endpoints) ListenAndServe(ctx context.Context) error {
	unaryInterceptor, streamInterceptor := middleware.Interceptors(
		endpoints.Middleware(e.c.Log, e.c.Metrics),
	)

	server := grpc.NewServer(
		grpc.Creds(peertracker.NewCredentials()),
		grpc.UnaryInterceptor(unaryInterceptor),
		grpc.StreamInterceptor(streamInterceptor),
	)

	e.registerServices(server)

	name := "Admin APIs"
	if e.c.DelegatedOnly {
		name = "DelegatedIdentity-only API"
	}
	l, err := e.createListener()
	if err != nil {
		e.c.Log.WithError(err).WithField("api", name).Error("Unable to create listener")
		return err
	}
	defer l.Close()
	log := e.c.Log.WithFields(logrus.Fields{
		telemetry.Network: l.Addr().Network(),
		telemetry.Address: l.Addr().String()})
	if e.c.DelegatedOnly {
		log = log.WithField("socket_group", e.c.SocketGroup)
	}
	log.Info("Starting " + name)
	if e.c.Listening != nil {
		close(e.c.Listening)
	}

	errChan := make(chan error)
	go func() { errChan <- server.Serve(l) }()

	select {
	case err = <-errChan:
		log.WithError(err).Error(name + " stopped prematurely")
		return err
	case <-ctx.Done():
		log.Info("Stopping " + name)
		server.Stop()
		<-errChan
		log.Info(name + " have stopped")
		return nil
	}
}

// registerServices registers only DelegatedIdentity on a delegated-only
// listener. Debug and Logger stay exclusive to the original Admin socket:
// Logger can change the process log level without delegate authorization.
func (e *Endpoints) registerServices(server *grpc.Server) {
	if !e.c.DelegatedOnly {
		e.registerDebugAPI(server)
	}
	e.registerDelegatedIdentityAPI(server)
	if !e.c.DelegatedOnly {
		e.registerLoggerAPI(server)
	}
}

func (e *Endpoints) registerDebugAPI(server *grpc.Server) {
	clk := clock.New()
	service := debugv1.New(debugv1.Config{
		Clock:       clk,
		Log:         e.c.Log.WithField(telemetry.SubsystemName, telemetry.DebugAPI),
		Manager:     e.c.Manager,
		Uptime:      e.c.Uptime,
		TrustDomain: e.c.TrustDomain,
	})

	debugv1.RegisterService(server, service)
}

func (e *Endpoints) registerLoggerAPI(server *grpc.Server) {
	service := loggerv1.New(loggerv1.Config{
		Log: e.c.RootLog,
	})

	loggerv1.RegisterService(server, service)
}

func (e *Endpoints) registerDelegatedIdentityAPI(server *grpc.Server) {
	service := delegatedidentityv1.New(delegatedidentityv1.Config{
		Manager:             e.c.Manager,
		Attestor:            e.c.Attestor,
		AuthorizedDelegates: e.c.AuthorizedDelegates,
		Metrics:             e.c.Metrics,
		Log:                 e.c.Log.WithField(telemetry.SubsystemName, telemetry.DelegatedIdentityAPI),
	})

	delegatedidentityv1.RegisterService(server, service)
}
