package smtpd

type Middleware func(conn *Connection, next Handler) Handler
type Handler func(conn *Connection)

type Wrapper func(next Wrapped) Wrapped
type Wrapped func()
