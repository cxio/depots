// Copyright 2024 of chainx.zh@gmail.com, All rights reserved.
// Use of this source code is governed by a MIT license.
// ---------------------------------------------------------------------------
// 基础配置集
// ----------
// 部分可由用户外部JSON配置修改，部分为程序内置值。
// 大部分配置文件存放于用户主目录下的 .depots/ 之内。
//
// 禁闭节点
// --------
// 程序运行过程中，不友好节点会被临时禁闭排除。
// 用户也可以配置一个节点清单，但它们也遵循同样的时效期。
// 禁闭配置文件（bans.json）在应用程序系统缓存目录下，如果不存在可手工创建。
// 内容为简单的地址（IP:Port）清单。
//
// @2024.11.30 cxio
///////////////////////////////////////////////////////////////////////////////
//

// Package config 全局配置集
package config

import (
	"net/netip"
	"time"
)

// 基本配置常量。
const (
	UserID     = ""   // 本节点的身份ID（群组时用）
	ServerTCP  = 7799 // 本地TCP服务端口
	ServerUDP  = 7790 // 本地UDP监听端口
	Depots     = 8    // 本类组网连接节点数
	Finders    = 3    // 连接Findings节点数
	BufferSize = 1024 // 连接读写缓冲区大小
	PloySeed   = ""   // 策略种子（默认值）
)

// 几个服务配置。
// 其中 Blockqs 和 Archives 为内部数据服务。
const (
	FindingsPort = 7788  // Findings服务器端口（TCP:Websocket）
	BlockqsIP    = ""    // 区块查询服务地址，外部配置
	BlockqsPort  = 17791 // 区块查询服务端口
	ArchivesIP   = ""    // 档案存储服务地址，外部配置
	ArchivesPort = 17792 // 档案存储服务端口
)

// 开发配置常量
// 可能关系到安全，不提供外部可配置。
const (
	DepotPatrol   = time.Minute * 10  // 本类节点连接切换巡查间隔
	BanExpired    = time.Hour * 2     // 恶意节点禁闭期限
	FinderExpired = time.Minute * 120 // Findings节点在线过期时长（2h）
)

// 本系统（depots:z）
const (
	Kind    = "depots" // 基础类别
	AppName = "ab"     // 本服务实现名
)

// 存储策略文件
// 存放于用户主目录内的.depots/ploys/子目录下。
// 二级子目录按类别值命名：
// - 0 存档类（Archives）
// - 1 区块链类（Blockqs）
const (
	PloyDir     = "ploys"          // 策略文件根目录
	PloyWhite0  = "whitelist.json" // 白名单
	PloyBlack0  = "blacklist.json" // 黑名单
	PloyGo      = "ploy.go"        // 策略扩展（Go）
	PloyLua     = "ploy.lua"       // 策略扩展（Lua）
	PloyGoFunc  = "main.Ploy"      // 策略函数接口名（Go）
	PloyLuaFunc = "ploy"           // 策略函数接口名（Lua）
)

// 日志文件名
const (
	LogDir       = "logs"       // 日志根目录（系统缓存根下）
	LogFile      = "depots.log" // 主程序日志
	LogPeerFile  = "peers.log"  // 有效连接节点历史
	LogDebugFile = "debug.log"  // 调试日志
)

// 几个配置文件。
// 大部分在用户主目录内的.depots/子目录下。
const (
	fileDir    = ".depots"      // 配置文件目录
	fileConfig = "config.hjson" // 基础配置文件
	filePeers  = "peers.json"   // 有效节点清单
	fileStakes = "stakes.hjson" // 服务器权益账户配置
	fileBans   = "bans.json"    // 禁闭节点配置
)

//
//////////////////////////////////////////////////////////////////////////////
//

// Peer 端点类型。
// 仅用于读取用户的节点配置。
type Peer struct {
	IP   netip.Addr `json:"ip"`             // 公网IP
	Port uint16     `json:"port,omitempty"` // 公网端口，作为Config成员时可选
}

func (p *Peer) String() string {
	return netip.AddrPortFrom(p.IP, p.Port).String()
}

// Config 基础配置。
type Config struct {
	Blockqs      Peer   // 区块查询服务配置
	Archives     Peer   // 档案存储服务配置
	UserID       string `json:"user_id,omitempty"`       // 本节点的身份ID（群组时用）
	FindingsPort int    `json:"findings_port,omitempty"` // Findings服务端口
	ServerTCP    int    `json:"tcp_port,omitempty"`      // 本地服务端口
	ServerUDP    int    `json:"udp_port,omitempty"`      // 本地服务端口（UDP）
	Depots       int    `json:"depots,omitempty"`        // 本类组网连接节点数
	Finders      int    `json:"finders,omitempty"`       // 连接Findings节点数
	BufferSize   int    `json:"buffer_size,omitempty"`   // 连接读写缓冲区大小
	LogDir       string `json:"log_dir,omitempty"`       // 日志根目录，注意空串有特定含义
	PloyLang     string `json:"ploy_lang,omitempty"`     // 策略函数实现语言
	PloySeed     string `json:"ploy_seed,omitempty"`     // 策略种子
}
