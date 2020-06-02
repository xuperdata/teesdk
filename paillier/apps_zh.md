## 基于paillier同态的数据隐私保护和授权管理

paiilier是一种加法同态算法，安全性依赖于大整数分解难题。paillier支持在加密状态下密文的加法和数乘运算。在区块链系统中可以用来做密文的安全计算。我们用golang实现了一套paillier加密算法，同时支持密文的所属权和使用权共享功能。

超级链基于paillier同态算法实现的数据隐私保护和授权管理相关组件如下：

1. TEE-SDK: https://github.com/xuperdata/teesdk

   实现了paillier插件

2. 超级链SDK:  https://github.com/xuperdata/xuper-sdk-go

   负责交易的封装，加密和解密

3. xuperchain: https://github.com/xuperchain/xuperchain

   超级链开源代码

### 部署和使用流程

1. 部署过程

   1). 下载并编译TEESDK

   ```
   git clone https://github.com/xuperdata/teesdk
   cd teesdk
   bash build.sh
   ```

   编译后会在build目录下产出libpaillier.so.0.0.1， 将这个文件和teesdk/paillier/xchain-plugin/paillierconfig.conf复制到xchain的pluginPath配置的路径下面。

   2). 拉取超级链最新代码： https://github.com/xuperchain/xuperchain , 注意编译的时候把 makefile的 **-mod=vendor**去掉，编译超级链，并且在xchain.conf增加如下配置：

   ```
   # 块广播模式
   blockBroadcaseMode: 0
   ...
   #可信环境的入口, optional
   wasm:
    driver: "xvm"
    enableUpgrade: false
    teeConfig:
      enable: on
      pluginPath: "/root/private-ledger-go-api/xchain_plugin/libpaillier.so.0.0.1"
      configPath: "/root/private-ledger-go-api/xchain_plugin/paillierconfig.conf"
    xvm:
      optLevel: 0
      
   #是否开启默认的XEndorser背书服务
   enableXEndorser: true
   ```

   3). 拉取超级链SDK最新的代码。配置sdk.yaml.tee

   ```
   tfConfig:
    teeConfig:
     svn: 0
     enable: off
     tmsport: 8082
     uid: "uid1"
     token: "token1"
     auditors:
       -
        publicder: /root/mesatee-core-standalone/release/services/auditors/godzilla/godzilla.public.der
        sign: /root/mesatee-core-standalone/release/services/auditors/godzilla/godzilla.sign.sha256
        enclaveinfoconfig: /root/mesatee-core-standalone/release/services/enclave_info.toml
   paillierConfig:
    enable: on
   ```

2. 测试

   可信应用开发参考合约paillier.cc；可信合约相关测试参考[main_paillier](https://github.com/xuperdata/xuper-sdk-go/blob/master/example/main_trust_counter.go)；paillier相关测试参考[pailliertest](https://github.com/xuperdata/teesdk/blob/master/paillier/paillier_test.go)。

#### 开发智能合约

合约用来存储密文数据和授权信息，并支持密文同态计算，合约中的表设计如下：

| dataid | owner | pubkey | content                 | User  | commitment                      |
| ------ | ----- | ------ | ----------------------- | ----- | ------------------------------- |
| 1      | owner | Pubkey | Cipher1                 | owner |                                 |
| 1      | owner | Pubkey | Cipher1                 | user  | ecdsaPub+sig(hash(cipher,user)) |
| 2      | owner | Pubkey | Cipher2                 | user  | ecdsaPub+sig(hash(cipher,user)) |
| 3      | owner | Pubkey | result(cipher1+cipher2) | user  |                                 |
| 4      | user  | usrPub | userCipher              | user  |                                 |

其中pubkey是用户提前生成好的paillier公钥。commitment是用户对密文数据和使用者地址的签名，加上用户的ecdsa公钥。

合约支持数据的增删改查、数据授权和密文计算功能，主要方法如下：

| 方法名称  | 入参                                 | 处理过程                                                     | 返回                 |
| --------- | ------------------------------------ | ------------------------------------------------------------ | -------------------- |
| store     | dataid, content, pubkey              | 插入记录，user是自己的地址                                   | “done” / "failed..." |
| authorize | dataid, user, commitment             | 添加新的一行，包括授权信息commitment                         | "done" / "failed..." |
| share     | dataid, addr, newid, content，pubkey | 线下利用使用者公钥加密明文数据，将新的密文和newid插入表中并赋予新owner | "done" / "failed..." |
| add       | dataid1, dataid2, newid              | 取出两个密文和对应的commitment，调用可信算子add方法，返回密文后添加新的一行数据 | "done" / "failed..." |

和基于tee的授权管理不同，这里的使用授权和数据所属权共享主要在链下进行计算，链只用来存储提前计算好的授权信息和新的密文数据。加法和乘法在链上进行。
