package teesdk 

type FuncCaller struct {
    Method string  `json:"method"`
    Args string     `json:"args"`
    Svn uint32   `json:"svn"`
    ContentSig string `json:"content_sig"`
    AddrHash   string `json:"addr_hash"`
}

type KMSCaller struct {
    Method string `json:"method"`// init
    Kds string   `json:"kds"`
    Svn uint32   `json:"svn"`
}
