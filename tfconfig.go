package teesdk

import (
	"github.com/xuperdata/teesdk/mesatee"
	"github.com/xuperdata/teesdk/paillier"
)

type TFConfig struct {
	TEEConfig      mesatee.TEEConfig       `yaml:"teeConfig"`
	PaillierConfig paillier.PaillierConfig `yaml:"paillierConfig"`
}
