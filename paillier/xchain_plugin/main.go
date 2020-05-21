package main

import (
	"encoding/json"
	"io/ioutil"
	"fmt"

	"github.com/golang/protobuf/proto"
	"gopkg.in/yaml.v2"

	"github.com/xuperdata/teesdk/paillier"
	"github.com/xuperdata/teesdk/paillier/xchain_plugin/pb"
)

var (
	client  *paillier.PaillierClient
	pconfig *paillier.PaillierConfig
)

func loadConfigFile(configPath string) (*paillier.PaillierConfig, error) {
	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	var nc paillier.PaillierConfig
	if err := yaml.Unmarshal(data, &nc); err != nil {
		return nil, err
	}
	return &nc, nil
}

func Init(confPath string) error {
	cfg, err := loadConfigFile(confPath)
	if err != nil {
		return err
	}
	pconfig = cfg
	client = paillier.NewPaillierClient()
	return nil
}

func Run(requestBuf []byte) ([]byte, error) {
	var (
		err       error
		tmpbuf    []byte
		tmpbufstr string
		plainMap  map[string]string
	)
	in := &pb.TrustFunctionCallRequest{}
	if err = proto.Unmarshal(requestBuf, in); err != nil {
		return nil, err
	}
	if pconfig == nil || !pconfig.Enable || client == nil {
		err = fmt.Errorf("IsEnabled is false, this node doest not enable paillier")
		return nil, err
	}
	if tmpbuf, err = json.Marshal(paillier.FuncCaller{
		Method: in.Method, Args: in.Args, Svn: in.Svn,
		Address: in.Address, PublicKey: in.PublicKey,
		Signature: in.Signature}); err != nil {
		return nil, err
	}
	if tmpbufstr, err = client.Submit("paillier", string(tmpbuf)); err != nil {
		return nil, err
	}
	if err = json.Unmarshal([]byte(tmpbufstr), &plainMap); err != nil {
		return nil, err
	}
	kvs := &pb.TrustFunctionCallResponse_Kvs{
		Kvs: &pb.KVPairs{},
	}
	for k, v := range plainMap {
		kvs.Kvs.Kv = append(kvs.Kvs.Kv, &pb.KVPair{Key: k, Value: v})
	}
	return proto.Marshal(&pb.TrustFunctionCallResponse{Results: kvs})
}

func main() {}
