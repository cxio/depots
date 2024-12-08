package msg

import (
	"crypto"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"io"

	"github.com/cloudflare/circl/dh/x25519"
	"github.com/cxio/findings/crypto/utilx"
	"golang.org/x/crypto/sha3"
)

const (
	// 不支持的算法标识
	failAlgor = "Unsupported algorithm identifier."

	// 密钥长度不足
	failKeylen = "The key length is insufficient."
)

var (
	// ErrShared 共享密钥构造错误
	ErrShared = errors.New("the public key is a low-order point.")
)

// KeySize 共享密钥长度
const KeySize = 32

// PublicKey 公钥引用类型（通用）
type PublicKey = crypto.PublicKey

// PrivateKey 私钥引用类型（通用）
type PrivateKey = crypto.PrivateKey

// Secret 共享密钥
type Secret [KeySize]byte

// Key25519 X25519密钥
type Key25519 x25519.Key

// Public 返回公钥
// @return 一个字节切片
func (k *Key25519) Public() PublicKey {
	buf := x25519.Key{}
	x25519.KeyGen(&buf, (*x25519.Key)(k))
	return buf[:]
}

// Equal 私钥相等比较
func (k *Key25519) Equal(x PrivateKey) bool {
	if priv, ok := x.(*x25519.Key); ok {
		return subtle.ConstantTimeCompare(priv[:], k[:]) == 1
	}
	return false
}

// DHTag 密钥交换算法标识
type DHTag int

// 几个常用密钥交换算法
const (
	DH_Tradi  DHTag = iota // 惯用DH算法（x25519）
	DH_X25519              // x25519曲线
	DH_ECp256              // ECDH-p256曲线
	DH_ECp384              // ECDH-p384曲线
)

// GenerateKey 创建密钥交换用私钥
// @tag 密钥交换算法标识
func GenerateKey(tag DHTag) (PrivateKey, error) {
	switch tag {
	case DH_Tradi:
		fallthrough
	case DH_X25519:
		return x25519PrivKey()
	case DH_ECp256:
		return ecdh.P256().GenerateKey(rand.Reader)
	case DH_ECp384:
		return ecdh.P384().GenerateKey(rand.Reader)
	}
	panic(failAlgor)
}

// Hash256SHA3 共享密钥哈希封装。
// 用 SHA3:Sum256 封装直接计算出的共享密钥。
// 用于外部封装以维持一致性。
func Hash256sha3(data []byte) *Secret {
	buf := sha3.Sum256(data)
	return (*Secret)(&buf)
}

// DHPack 密钥交换包
type DHPack struct {
	Algor   DHTag      // 算法标识
	privkey PrivateKey // 私钥数据
}

// NewDHPack 创建一个密钥交换包。
// 只有被支持的算法才能创建实例，否则返回nil。
// 外部注意检查返回的结果。
func NewDHPack(tag DHTag, priv PrivateKey) *DHPack {
	switch tag {
	case DH_Tradi:
		// tag = DH_X25519
	case DH_X25519:
	case DH_ECp256:
	case DH_ECp384:
	default:
		return nil
	}
	return &DHPack{Algor: tag, privkey: priv}
}

// SharedKey 构造共享密钥
// 内部计算的共享密钥会被哈希（SHA3:256）一次后返回。
// @public 乙方公钥
// @return 直接可用的共享密钥
func (dh *DHPack) SharedKey(public []byte) (*Secret, error) {
	switch dh.Algor {
	case DH_Tradi:
		fallthrough
	case DH_X25519:
		return sharedX25519(dh.privkey, public)
	case DH_ECp256:
		fallthrough
	case DH_ECp384:
		return sharedECDH(dh.privkey, public)
	}
	panic(failAlgor)
}

// PublicBytes 提取公钥字节序列。
// 注意：算法和私钥应当匹配，否则会抛出恐慌。
func (dh *DHPack) PublicBytes() []byte {
	switch dh.Algor {
	case DH_Tradi:
		fallthrough
	case DH_X25519:
		priv := dh.privkey.(*Key25519)
		return priv.Public().([]byte)
	case DH_ECp256:
		fallthrough
	case DH_ECp384:
		priv := dh.privkey.(*ecdh.PrivateKey)
		return priv.PublicKey().Bytes()
	}
	panic(failAlgor)
}

// Encrypt 加密消息
// 内部自动构建共享密钥，采用 cipher.GCM 算法。
// @public 对端公钥序列
// @msg    待加密消息
// @return 加密后的密文
func (dh *DHPack) Encrypt(public []byte, msg []byte) ([]byte, error) {
	key, err := dh.SharedKey(public)
	if err != nil {
		return nil, err
	}
	return utilx.Encrypt(msg, (*[32]byte)(key))
}

// Decrypt 解密消息
// 内部自动构建共享密钥，采用 cipher.GCM 算法。
func (dh *DHPack) Decrypt(public []byte, data []byte) ([]byte, error) {
	key, err := dh.SharedKey(public)
	if err != nil {
		return nil, err
	}
	return utilx.Decrypt(data, (*[32]byte)(key))
}

//
// 私有辅助
//////////////////////////////////////////////////////////////////////////////

// 创建X25519私钥。
func x25519PrivKey() (*Key25519, error) {
	bs, err := randomBytes(x25519.Size)
	if err != nil {
		return nil, err
	}
	return (*Key25519)(bs), nil
}

// 构建 X25519（RFC-7748）共享密钥
// 如果公钥为 low-order point，会返回错误，构造失败。
// 注：初始的共享密钥会经过一层哈希封装（SHA3:256）。
// @private 己方私钥
// @public 对方公钥的字节序列
func sharedX25519(private PrivateKey, public []byte) (*Secret, error) {
	buf := x25519.Key{}

	if len(public) != x25519.Size {
		return nil, ErrShared
	}
	priv := private.(*Key25519)

	if !x25519.Shared(&buf, (*x25519.Key)(priv), (*x25519.Key)(public)) {
		return nil, ErrShared
	}
	// SHA3:256 隐匿封装
	return Hash256sha3(buf[:]), nil
}

// 构建 NIST 曲线共享密钥
// 如果计算的共享密钥全为零，会返回错误，构造失败。
// - NIST P-256 (FIPS 186-3, section D.2.3)
// - NIST P-384 (FIPS 186-3, section D.2.4)
// 注：初始的共享密钥会经过一层哈希封装（SHA3:256）。
// @private 己方私钥
// @public 对方公钥的字节序列
func sharedECDH(private PrivateKey, public []byte) (*Secret, error) {
	priv := private.(*ecdh.PrivateKey)
	curve := priv.Curve()

	pub, err := curve.NewPublicKey(public)
	if err != nil {
		return nil, err
	}
	buf, err := priv.ECDH(pub)
	if err != nil {
		return nil, err
	}
	// SHA3:256 隐匿封装
	return Hash256sha3(buf), nil
}

// 创建随机序列（安全）
// @size 需要的序列长度
func randomBytes(size int) ([]byte, error) {
	buf := make([]byte, size)

	_, err := io.ReadFull(rand.Reader, buf)
	if err != nil {
		return nil, err
	}
	return buf, nil
}
