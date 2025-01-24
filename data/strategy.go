// Package data 与数据操作相关。
// 比如数据的存储策略、白名单和黑名单等。
package data

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/cxio/depots/base"
	"github.com/cxio/depots/config"
	"github.com/traefik/yaegi/interp"
	"github.com/traefik/yaegi/stdlib"
	lua "github.com/yuin/gopher-lua"
)

// Log 日志记录器引用
var Log = base.Log

// 几个错误信息模板。
var (
	// 找不到策略函数。
	ErrFuncFind = errors.New("failed to find ploy function")
	// 策略函数签名错误。
	ErrFuncSign = errors.New("invalid Ploy function signature")
)

// Strategy 定义策略接口
type Strategy interface {
	// 主判断函数。
	// 根据目标数据ID判断是否符合存储要求。
	// 数据大小可以是一个参考项。
	Pass(id []byte, size int) bool

	// 完成可能需要的资源回收。
	Close()
}

// MatchList 定义匹配列表
type MatchList struct {
	patterns map[string]struct{}
}

func NewMatchList() *MatchList {
	return &MatchList{
		patterns: make(map[string]struct{}),
	}
}

// Add 添加一条匹配式
// 不正确的正则表达式在测试时会被忽略，但会错误记入日志。
// 应当在程序初始启动时设置。
// @pattern Go正则表达式串
func (m *MatchList) Add(pattern string) {
	m.patterns[pattern] = struct{}{}
}

// Match 检查目标id是否匹配。
func (m *MatchList) Match(id []byte) bool {
	for pattern := range m.patterns {
		matched, err := regexp.Match(pattern, id)

		if err != nil {
			Log.Println("[Error]", err)
		}
		if matched {
			return true
		}
	}
	return false
}

// PolicyManager 策略管理器
type PolicyManager struct {
	whitelist *MatchList
	blacklist *MatchList
	strategy  Strategy
}

// NewPolicyManager 创建策略管理器。
// 内部包含黑白名单的处理，
// 优先级：白名单 > 黑名单 > 策略函数
func NewPolicyManager() *PolicyManager {
	return &PolicyManager{
		whitelist: NewMatchList(),
		blacklist: NewMatchList(),
	}
}

// Whitelist 设置白名单。
// @list 名单条目清单
func (pm *PolicyManager) Whitelist(list []string) {
	for _, its := range list {
		pm.whitelist.Add(its)
	}
}

// Blacklist 设置黑名单。
// @list 名单条目清单
func (pm *PolicyManager) Blacklist(list []string) {
	for _, its := range list {
		pm.blacklist.Add(its)
	}
}

// Strategy 设置策略处理器。
// @iter 策略实现对象（Lua|Go|...）
func (pm *PolicyManager) Strategy(iter Strategy) {
	if pm.strategy != nil {
		pm.strategy.Close()
	}
	pm.strategy = iter
}

// Pass 策略通关检查。
// @id 目标数据ID
// @size 目标数据大小
// @return 是否通过（确定存储）
func (pm *PolicyManager) Pass(id []byte, size int) bool {
	// 白名单检查
	if pm.whitelist.Match(id) {
		return true
	}
	// 黑名单检查
	if pm.blacklist.Match(id) {
		return false
	}
	// 脚本检查
	if pm.strategy != nil {
		return pm.strategy.Pass(id, size)
	}
	return false
}

// Close 关闭策略管理器。
// 执行必要的资源清理，在退出程序前执行。
func (pm *PolicyManager) Close() {
	pm.whitelist = nil
	pm.blacklist = nil
	pm.strategy.Close()
}

//
// Lua 语言实现（Strategy）
//////////////////////////////////////////////////////////////////////////////

// LuaScript Lua脚本策略处理实现。
type LuaScript struct {
	code  string
	state *lua.LState
	call  lua.LValue
}

// NewLuaScript 新建一个Lua脚本策略器。
func NewLuaScript(code string) (*LuaScript, error) {
	ls := &LuaScript{
		code:  code,
		state: lua.NewState(),
	}
	if err := ls.init(); err != nil {
		ls.Close()
		return nil, fmt.Errorf("lua script init failed: %w", err)
	}
	return ls, nil
}

// 执行Lua脚本代码，获取处理函数。
func (ls *LuaScript) init() error {
	if err := ls.state.DoString(ls.code); err != nil {
		return err
	}
	f := ls.state.GetGlobal(config.PloyLuaFunc)

	if f.Type() != lua.LTFunction {
		return ErrFuncFind
	}
	ls.call = f
	return nil
}

// Pass 策略脚本判断。
func (ls *LuaScript) Pass(id []byte, size int) bool {
	if ls.state == nil || ls.call == nil {
		Log.Println("[Warning] ploy not defined with Lua")
		return false
	}

	ls.state.Push(ls.call)
	ls.state.Push(lua.LString(id))
	ls.state.Push(lua.LNumber(size))

	err := ls.state.PCall(2, 1, nil)
	if err != nil {
		Log.Println("[Error] failed to call ploy function:", err)
		return false
	}

	ret := ls.state.Get(-1)
	ls.state.Pop(1)

	if ret.Type() == lua.LTBool {
		return lua.LVAsBool(ret)
	}

	Log.Println("[Error] invalid return type from ploy function")
	return false
}

// Close 关闭脚本执行环境。
func (ls *LuaScript) Close() {
	if ls.state != nil {
		ls.state.Close()
	}
}

//
// Go 语言实现（Strategy）
//////////////////////////////////////////////////////////////////////////////

// GoScript Go脚本策略处理实现。
type GoScript struct {
	code string
	call func([]byte, int) bool
}

// NewGoScript 新建Go脚本策略器。
func NewGoScript(code string) (*GoScript, error) {
	gs := &GoScript{
		code: code,
		call: nil,
	}
	if err := gs.init(); err != nil {
		return nil, fmt.Errorf("go script init failed: %w", err)
	}
	return gs, nil
}

// 初始构造脚本为策略函数
func (gs *GoScript) init() error {
	i := interp.New(interp.Options{})
	i.Use(stdlib.Symbols)

	_, err := i.Eval(gs.code)
	if err != nil {
		return err
	}
	v, err := i.Eval(config.PloyGoFunc)
	if err != nil {
		return err
	}
	f, ok := v.Interface().(func([]byte, int) bool)
	if !ok {
		return ErrFuncSign
	}
	gs.call = f

	return nil
}

// Pass 策略脚本判断。
func (gs *GoScript) Pass(id []byte, size int) bool {
	if gs.call == nil {
		Log.Println("[Warning] ploy not defined with Go")
		return false
	}
	return gs.call(id, size)
}

// Close 关闭脚本环境。
// 注：无需操作，完成接口
func (gs *GoScript) Close() {}
