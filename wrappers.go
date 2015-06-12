package smtpd

type Middleware func(next Handler) Handler
type Handler func(conn *Connection)

type Wrapper func(next Wrapped) Wrapped
type Wrapped func()
