package packet

import (
	"encoding/binary"
	"errors"
	"net/netip"

	"github.com/cxio/depots/base"
	"github.com/cxio/depots/crypto/msg"
	"github.com/cxio/findings/stun"
	"google.golang.org/protobuf/proto"
)

// Version 数据包版本（0xf）
const Version = 0b0000_1111

// HopsMax 转播跳数最大值。
const HopsMax = 0x0F

// NAT 层级类型引用
type NatLevel = stun.NatLevel

// NAT 的4个层级。
const (
	NAT_LEVEL_UNDEFINED NatLevel = -1                  // （未定义）
	NAT_LEVEL_NULL               = stun.NAT_LEVEL_NULL // Public | Public@UPnP | Full Cone
	NAT_LEVEL_RC                 = stun.NAT_LEVEL_RC   // Restricted Cone (RC)
	NAT_LEVEL_PRC                = stun.NAT_LEVEL_PRC  // Port Restricted Cone (P-RC)
	NAT_LEVEL_SYM                = stun.NAT_LEVEL_SYM  // Symmetric NAT (Sym) | Sym UDP Firewall
)

// DHTag 类型引用（密钥交换）
type DHTag = msg.DHTag

// DHPack 类型引用（密钥交换）
type DHPack = msg.DHPack

// SignTag 类型引用（签名）
type SignTag = msg.SignTag

// SignPack 类型引用（签名）
type SignPack = msg.SignPack

// 三个消息包标识
const (
	PACKET_PROBE byte = iota // 探测包
	PACKET_QUEST             // 询问包
	PACKET_REPLY             // 回复包
)

var (
	// ErrHops 数据包跳数超限错误
	ErrHops = errors.New("packet forwarding hops exceeds the limit")

	// ErrAlgor 算法标识错误
	ErrAlgor = errors.New("target algorithm not supported")

	// ErrSign 签名验证失败错误
	ErrSign = errors.New("signature verification failed")

	// IP 解析错误。
	ErrParseIP = errors.New("parse ip bytes failed")
)

// 通用日志记录器
var loger = base.Log

// 数据类别
type Kind byte

// 基础数据类别
const (
	KIND_ARCHIVE    Kind = iota // 文档类
	KIND_BLOCKCHAIN             // 区块链类
)

// Base 基本信息
type Base struct {
	Ver   int      // 数据包版本
	ID    uint64   // 询问ID
	Hops  int      // 转播跳数
	Level NatLevel // 节点NAT层级
}

// NewBase 创建基础信息包
// 如果传入的NAT层级非法，视为Sym（最差）。
// @ver  版本号
// @id   数据查询包标识
// @hops 转播跳数累计
// @lev  节点NAT层级
func NewBase(ver int, id uint64, hops int, lev NatLevel) *Base {
	if lev < 0 ||
		lev > NAT_LEVEL_SYM {
		loger.Printf("[Warning] NAT level: %d is invalid.\n", lev)
		lev = NAT_LEVEL_SYM
	}
	return &Base{
		Ver:   ver,
		ID:    id,
		Hops:  hops,
		Level: lev,
	}
}

// HopAdd 增加跳数
// 如果跳数超出限制，返回一个错误。
// 注：通常应当只增加1跳！
func (b *Base) HopAdd(n int) error {
	b.Hops += n
	if b.Hops > HopsMax {
		return ErrHops
	}
	return nil
}

// VersionOK 版本是否兼容
func (b *Base) VersionOK(ver int) bool {
	return ver >= b.Ver
}

// Data 数据信息
type Data struct {
	Kind  Kind   // 数据类别（大类）
	Index []byte // 数据索引
	Size  uint32 // 数据大小（字节数）
}

// NewData 创建数据信息包
func NewData(kind Kind, index []byte, size uint32) *Data {
	return &Data{
		Kind:  kind,
		Index: index,
		Size:  size,
	}
}

// AidInfo 协助信息
// - 数据节点自身的信息。
// - 支持打洞服务的Findings节点信息。
type AidInfo struct {
	Network string     // 数据节点网络（websocket|dtls|tcp|udp）
	IP      netip.Addr // 数据节点IP
	Port    int        // 数据节点通讯端口
	Fip     netip.Addr // Findings节点IP
	Fport   int        // Findings节点服务端口
	Fkind   string     // 数据节点的Findings登记类别名
}

//
// 编解码（protoBuf）
//////////////////////////////////////////////////////////////////////////////

// EncodeQuest 编码询问包
// @b  基础信息包
// @d  请求的数据信息
// @dp 密钥交换包
func EncodeQuest(b *Base, d *Data, dh *DHPack) ([]byte, error) {
	buf := &Quest{
		Ver:    int32(b.Ver),
		Id:     b.ID,
		Hops:   int32(b.Hops),
		Algor:  int32(dh.Algor),
		Pubkey: dh.PublicBytes(),
		Level:  int32(b.Level),
		Kind:   int32(d.Kind),
		Index:  d.Index,
		Size:   d.Size,
	}
	return proto.Marshal(buf)
}

// DecodeQuest 解码询问包
// @return1 基础信息包
// @return2 目标数据信息
// @return3 公钥算法，-1表示无效值
// @return4 公钥字节序列
func DecodeQuest(data []byte) (*Base, *Data, DHTag, []byte, error) {
	buf := &Quest{}

	if err := proto.Unmarshal(data, buf); err != nil {
		return nil, nil, msg.DH_INVALID, nil, err
	}
	b := NewBase(
		int(buf.Ver),
		buf.Id,
		int(buf.Hops),
		stun.NatLevel(buf.Level),
	)
	d := NewData(Kind(buf.Kind), buf.Index, buf.Size)

	return b, d, DHTag(buf.Algor), buf.Pubkey, nil
}

// EncodeProbe 编码探测包
// @b  基础信息包
// @d  请求的数据信息
// @sp 签名封包
func EncodeProbe(b *Base, d *Data, sp *SignPack) ([]byte, error) {
	// 数据消息
	msg := DataMessage(byte(d.Kind), d.Index, d.Size)

	buf := &Probe{
		Ver:    int32(b.Ver),
		Hops:   int32(b.Hops),
		Algor:  int32(sp.Algor),
		Pubkey: sp.PublicBytes(),
		Signd:  sp.Sign(msg),
		Kind:   int32(d.Kind),
		Index:  d.Index,
		Size:   uint32(d.Size),
	}
	return proto.Marshal(buf)
}

// DecodeProbe 解码探测包
// 如果存在公钥，内部会先验证签名数据的有效性。
// 返回的公钥可用于外部的支持清单核实。
// @return1 基础信息包
// @return2 目标数据信息
// @return3 公钥字节序列
func DecodeProbe(data []byte) (*Base, *Data, []byte, error) {
	buf := &Probe{}

	if err := proto.Unmarshal(data, buf); err != nil {
		return nil, nil, nil, err
	}
	// 如果有签名（可选）
	if len(buf.Pubkey) > 0 {
		sp := msg.NewSignPack(SignTag(buf.Algor), nil)
		if sp == nil {
			return nil, nil, nil, ErrAlgor
		}
		// 验证签名
		msg := DataMessage(byte(buf.Algor), buf.Index, buf.Size)

		if !sp.Verify(buf.Pubkey, msg, buf.Signd) {
			return nil, nil, nil, ErrSign
		}
	}
	b := NewBase(int(buf.Ver), 0, int(buf.Hops), NAT_LEVEL_UNDEFINED)
	d := NewData(Kind(buf.Kind), buf.Index, buf.Size)

	return b, d, buf.Pubkey, nil
}

// EncodeReply 编码回复包
// 连系信息会被加密传输，
// 密钥交换包用于加密连系信息，以及输出自己的公钥。
// @b   基础信息
// @c   连系信息
// @dh  密钥交换包
// @pub 对端公钥序列
func EncodeReply(b *Base, a *AidInfo, dh *DHPack, pub []byte) ([]byte, error) {
	data, err := EncodeContact(b, a)
	if err != nil {
		return nil, err
	}
	// 连系信息加密
	xdata, err := dh.Encrypt(pub, data)
	if err != nil {
		return nil, err
	}
	buf := &Reply{
		Ver:     int32(b.Ver),
		Id:      b.ID,
		Pubkey:  dh.PublicBytes(),
		Contact: xdata,
	}
	return proto.Marshal(buf)
}

// DecodeReply 解码回复包
// 内部的连系信息已加密，需要解密（GCM）。
// @data 已编码数据
// @dh 密钥交换封包
// @return1 基础信息
// @return2 连系信息
func DecodeReply(data []byte, dh *DHPack) (*Base, *AidInfo, error) {
	buf := &Reply{}

	if err := proto.Unmarshal(data, buf); err != nil {
		return nil, nil, err
	}
	// 连系信息解密
	cdata, err := dh.Decrypt(buf.Pubkey, buf.Contact)
	if err != nil {
		return nil, nil, err
	}
	return DecodeContact(cdata, int(buf.Ver), buf.Id)
}

// EncodeContact 编码连系信息。
// @b 基础信息
// @a 连系协助信息
func EncodeContact(b *Base, a *AidInfo) ([]byte, error) {
	buf := &Contact{
		Hops:  int32(b.Hops),
		Level: int32(b.Level),
		Xnet:  a.Network,
		Ip:    a.IP.AsSlice(),
		Port:  int32(a.Port),
		Fip:   a.Fip.AsSlice(),
		Fport: int32(a.Fport),
		Fkind: a.Fkind,
	}
	return proto.Marshal(buf)
}

// DecodeContact 解码连系信息。
// @data 已解密编码数据
// @ver  版本信息
// @id   询问ID
// @return1 基础信息
// @return2 连系协助信息
func DecodeContact(data []byte, ver int, id uint64) (*Base, *AidInfo, error) {
	buf := &Contact{}

	if err := proto.Unmarshal(data, buf); err != nil {
		return nil, nil, err
	}
	// 数据节点IP
	ip, ok := netip.AddrFromSlice(buf.Ip)
	if !ok {
		return nil, nil, ErrParseIP
	}
	var fip netip.Addr

	// Findings 可选
	if len(buf.Fip) > 0 {
		fip, ok = netip.AddrFromSlice(buf.Fip)
		if !ok {
			return nil, nil, ErrParseIP
		}
	}
	a := AidInfo{
		Network: buf.Xnet,
		IP:      ip,
		Port:    int(buf.Port),
		Fip:     fip,
		Fport:   int(buf.Fport),
		Fkind:   buf.Fkind,
	}
	return NewBase(ver, id, int(buf.Hops), NatLevel(buf.Level)), &a, nil
}

//
// 辅助工具
//////////////////////////////////////////////////////////////////////////////

// DataMessage 构建数据消息
// 用于对目标数据的基本信息执行签名。
// 串联：
// - 数据类别：1字节
// - 索引：n字节，原始顺序
// - 大小：大端序，可选
func DataMessage(kind byte, index []byte, size uint32) []byte {
	n := 1 + len(index)
	if size > 0 {
		n += 4
	}
	buf := make([]byte, n)
	buf[0] = kind
	copy(buf[1:], index)

	if size > 0 {
		// 大端序
		binary.BigEndian.PutUint32(buf[n-4:], size)
	}
	return buf
}
