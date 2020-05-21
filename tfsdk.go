package teesdk

type TrustClient interface {
	Close()
	Submit(method string, cipher string) (string, error)
}
