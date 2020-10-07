package ably

import (
	"net/http"
	"time"

	"github.com/ably/ably-go/ably/proto"
)

// The Realtime libraries establish and maintain a persistent connection
// to Ably enabling extremely low latency broadcasting of messages and presence
// state.
type Realtime struct {
	Auth       *Auth
	Channels   *Channels
	Connection *Connection

	rest *REST
}

// NewRealtime constructs a new Realtime.
func NewRealtime(options ClientOptions) (*Realtime, error) {
	c := &Realtime{}
	rest, err := NewREST(options)
	if err != nil {
		return nil, err
	}
	c.rest = rest
	c.Auth = rest.Auth
	c.Channels = newChannels(c)
	conn, err := newConn(c.opts(), rest.Auth, connCallbacks{
		c.onChannelMsg,
		c.onReconnected,
		c.onReconnectionFailed,
	})
	conn.internalEmitter.OnAll(func(change ConnectionStateChange) {
		c.Channels.broadcastConnStateChange(change)
	})
	if err != nil {
		return nil, err
	}
	c.Connection = conn
	return c, nil
}

// Connect is the same as Connection.Connect.
func (c *Realtime) Connect() {
	c.Connection.Connect()
}

// Close is the same as Connection.Close.
func (c *Realtime) Close() {
	c.Connection.Close()
}

// Stats gives the clients metrics according to the given parameters. The
// returned result can be inspected for the statistics via the Stats()
// method.
func (c *Realtime) Stats(params *PaginateParams) (*PaginatedResult, error) {
	return c.rest.Stats(params)
}

// Time
func (c *Realtime) Time() (time.Time, error) {
	return c.rest.Time()
}

func (c *Realtime) onChannelMsg(msg *proto.ProtocolMessage) {
	c.Channels.Get(msg.Channel).notify(msg)
}

func (c *Realtime) onReconnected(err *proto.ErrorInfo, isNewID bool) {
	if err == nil /* RTN15c3 */ && !isNewID /* RTN15g3 */ {
		return
	}

	for _, ch := range c.Channels.All() {
		switch ch.State() {
		// TODO: SUSPENDED
		case ChannelStateAttaching, ChannelStateAttached:
			ch.mayAttach(false, false)
		}
	}
}

func (c *Realtime) onReconnectionFailed(err *proto.ErrorInfo) {
	for _, ch := range c.Channels.All() {
		ch.setState(ChannelStateFailed, newErrorFromProto(err))
	}
}

func isTokenError(err *proto.ErrorInfo) bool {
	return err.StatusCode == http.StatusUnauthorized && (40140 <= err.Code && err.Code < 40150)
}

func (c *Realtime) opts() *clientOptions {
	return c.rest.opts
}

func (c *Realtime) logger() *LoggerOptions {
	return c.rest.logger()
}
