package main

import (
	"encoding/json"
	"fmt"
	"path"

	"github.com/golang/protobuf/proto"
	"github.com/spf13/viper"

	"github.com/xuperdata/teesdk"
	"github.com/xuperdata/teesdk/xchain_plugin/pb"
)

var (
	client  *teesdk.TEEClient
	tconfig *teesdk.TEEConfig
)

func loadConfigFile(configPath string, confName string) (nc teesdk.TEEConfig,err error) {
        viper.SetConfigName(confName)
        viper.AddConfigPath(configPath)
        err = viper.ReadInConfig()
        if err != nil {
		return
        }
        if err = viper.Unmarshal(&nc); err != nil {
		return
        }
	return
}


func Init(confPath string) error {
	confName := path.Base(confPath)
	dirName := path.Dir(confPath)
	cfg, err := loadConfigFile(dirName, confName)
	if err != nil {
		return err
	}
	tconfig = &cfg
	client = teesdk.NewTEEClient(cfg.Uid,
		cfg.Token,
		cfg.Auditors[0].PublicDer,
		cfg.Auditors[0].Sign,
		cfg.Auditors[0].EnclaveInfoConfig,
		cfg.TMSPort,
		cfg.TDFSPort)
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
	if tconfig == nil || !tconfig.Enable || client == nil {
		err = fmt.Errorf("IsTFCEnabled is false, this node doest not enable TEE")
		return nil, err
	}
	if tmpbuf, err = json.Marshal(teesdk.FuncCaller{
		Method: in.Method, Args: in.Args, Svn: in.Svn,
		Address: in.Address}); err != nil {
		return nil, err
	}
	if tmpbufstr, err = client.Submit("xchaintf", string(tmpbuf)); err != nil {
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
