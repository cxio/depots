package msg

import (
	"crypto/ed25519"
	"crypto/rand"
)

// SignTag 签名算法标识
type SignTag int

// 几个常用签名算法
// 注：当前仅定义了ed25519。
const (
	SIGN_Tradi   SignTag = iota // 惯用签名算法（ed25519）
	SIGN_ED25519                // ed25519 签名
)

// GenerateSignKey 创建签名用私钥
// @tag 签名算法标识
func GenerateSignKey(tag SignTag) (PrivateKey, error) {
	switch tag {
	case SIGN_Tradi:
		fallthrough
	case SIGN_ED25519:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv, err
	}
	panic(failAlgor)
}

// SignPack 签名封包
type SignPack struct {
	Algor   SignTag    // 算法标识
	private PrivateKey // 签名私钥
}

// NewSignPack 创建一个签名封包
// 只有被支持的算法才能创建实例，否则返回nil。
// 注：
// 如果只是用于验证（Verify），priv可以为nil。
func NewSignPack(tag SignTag, priv PrivateKey) *SignPack {
	switch tag {
	case SIGN_Tradi:
		// tag = SIGN_ED25519
	case SIGN_ED25519:
		// 占位即可
	default:
		return nil
	}
	return &SignPack{Algor: tag, private: priv}
}

// Sign 签名消息。
// @msg 待签名的消息
// @return 签名数据
func (sp *SignPack) Sign(msg []byte) []byte {
	switch sp.Algor {
	case SIGN_Tradi:
		fallthrough
	case SIGN_ED25519:
		priv := sp.private.(ed25519.PrivateKey)
		return ed25519.Sign(priv, msg)
	}
	panic(failAlgor)
}

// Verify 验证消息是否合法
// 仅验证消息时，构造SignPack仅需传递算法标识，
// 公钥为外来数据，无需私钥信息。
// @alg 算法标识
// @pub 公钥数据
// @msg 验证的消息
// @sig 签名数据（待验证目标）
func (sp *SignPack) Verify(pub []byte, msg, sig []byte) bool {
	switch sp.Algor {
	case SIGN_Tradi:
		fallthrough
	case SIGN_ED25519:
		return ed25519.Verify(ed25519.PublicKey(pub), msg, sig)
	}
	panic(failAlgor)
}

// PublicBytes 提取公钥字节序列。
func (sp *SignPack) PublicBytes() []byte {
	switch sp.Algor {
	case SIGN_Tradi:
		fallthrough
	case SIGN_ED25519:
		priv := sp.private.(ed25519.PrivateKey)
		return []byte(priv.Public().(ed25519.PublicKey))
	}
	panic(failAlgor)
}
