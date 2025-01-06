// Package data 与数据操作相关。
// 比如数据的存储策略、白名单和黑名单等。
package data

import (
	"errors"
	"log"
	"regexp"

	"github.com/cxio/depots/base"
	"github.com/cxio/depots/config"
	"github.com/traefik/yaegi/interp"
	"github.com/traefik/yaegi/stdlib"
	lua "github.com/yuin/gopher-lua"
)

// Log 日志记录器引用
var Log = base.Log

// 策略脚本所用语言类型
type PloyLang int

// 当前仅支持两种语言定义。
const (
	PLOYLANG_GO  PloyLang = iota + 1 // Go 语言实施
	PLOYLANG_LUA                     // Lua 语言实施
)

// Ployor 策略函数签名。
// 注意声明仅是一个引用（语法糖），不然无法匹配。
type Ployor = func([]byte, int) bool

// 几个错误信息模板。
var (
	// 找不到策略函数。
	ErrFuncFind = errors.New("failed to find ploy function")
	// 策略函数签名错误。
	ErrFuncSign = errors.New("invalid Ploy function signature")
)

// PloyScript 策略脚本。
// lang 仅指定一种语言即可，并非两种同时使用。
type ployScript struct {
	lang PloyLang // 脚本语言
	code string   // 脚本内容

	goPloyFunc  Ployor      // Go 策略脚本函数引用
	luaState    *lua.LState // Lua 状态机引用
	luaPloyFunc lua.LValue  // Lua 策略脚本函数引用
}

// Passed 策略判断。
func (p *ployScript) Passed(id []byte, size int) bool {
	switch p.lang {
	case PLOYLANG_GO:
		return p.goPloyFunc != nil && p.goPloyFunc(id, size)
	case PLOYLANG_LUA:
		return p.ployLua(id, size)
	}
	return false // 实际上不会执行到此
}

// 初始化解析Go代码，提取Go版策略函数。
func (p *ployScript) initGo(code string) error {
	i := interp.New(interp.Options{})
	i.Use(stdlib.Symbols)

	_, err := i.Eval(code)
	if err != nil {
		return nil
	}
	v, err := i.Eval(config.PloyGoFunc)
	if err != nil {
		return nil
	}
	ployFunc, ok := v.Interface().(Ployor)
	if !ok {
		return ErrFuncSign
	}
	p.goPloyFunc = ployFunc
	return nil
}

// 初始化Lua环境&策略编码。
func (p *ployScript) initLua(code string) error {
	luaState := lua.NewState()
	if err := luaState.DoString(code); err != nil {
		return err
	}

	luaPloyFunc := luaState.GetGlobal(config.PloyLuaFunc)
	if luaPloyFunc.Type() != lua.LTFunction {
		return ErrFuncFind
	}
	// 之前的遗留清理。
	if p.luaState != nil {
		p.luaState.Close()
	}
	p.luaState = luaState
	p.luaPloyFunc = luaPloyFunc

	return nil
}

// 调用Lua策略脚本。
func (p *ployScript) ployLua(id []byte, size int) bool {
	if p.luaState == nil || p.luaPloyFunc == nil {
		return false
	}

	p.luaState.Push(p.luaPloyFunc)
	p.luaState.Push(lua.LString(id))
	p.luaState.Push(lua.LNumber(size))

	err := p.luaState.PCall(2, 1, nil)
	if err != nil {
		Log.Println("[Error] failed to call ploy function:", err)
		return false
	}

	ret := p.luaState.Get(-1)
	p.luaState.Pop(1)

	if ret.Type() == lua.LTBool {
		return lua.LVAsBool(ret)
	}

	Log.Println("[Error] invalid return type from ploy function")
	return false
}

// 创建策略脚本。
// 返回错误时，内部的部分字段为nil，但不会影响后续的调用。
// 不过调用.Passed()会返回false。
func newPloyScript(lang PloyLang, code string) (*ployScript, error) {
	ps := &ployScript{
		lang: lang,
		code: code,
	}
	var err error

	switch lang {
	case PLOYLANG_GO:
		err = ps.initGo(code)
	case PLOYLANG_LUA:
		err = ps.initLua(code)
	default:
		log.Fatalln("invalid ploy script language")
	}
	return ps, err
}

// Ploys 策略集。
// 包含白名单、黑名单和策略脚本。
type Ploys struct {
	whites map[string]struct{} // 白名单匹配式集
	blacks map[string]struct{} // 黑名单匹配式集
	script *ployScript         // 策略脚本
}

// NewPloys 创建策略集。
func NewPloys() *Ploys {
	return &Ploys{
		whites: make(map[string]struct{}),
		blacks: make(map[string]struct{}),
	}
}

// PutScript 设置策略脚本。
// 通常只需设置一次，因为策略脚本不会改变。
// 如果需要动态改变，重新设置一次即可（但非并发安全）。
// @lang 脚本语言
// @code 脚本文本
func (p *Ploys) PutScript(lang PloyLang, code string) {
	ps, err := newPloyScript(lang, code)
	if err != nil {
		Log.Println("[Error] failed to create ploy script:", err)
		return
	}
	p.script = ps
}

// PushWhitelist 添加白名单。
// 不正确的正则表达式在测试时会被忽略（错误记入日志）。
// 需在程序初始启动时载入名单，非并发安全。
// @list 白名单条目（Go正则表达式）清单
func (p *Ploys) PushWhitelist(list []string) {
	for _, its := range list {
		p.whites[its] = struct{}{}
	}
}

// PushBlacklist 添加黑名单。
// 说明同上白名单。
// @list 黑名单条目（Go正则表达式）清单
func (p *Ploys) PushBlacklist(list []string) {
	for _, its := range list {
		p.blacks[its] = struct{}{}
	}
}

// Want 是否需要存储。
// 根据目标数据ID判断是否符合存储要求。
// 这是存储判断的入口函数，内部会处理策略集和黑白名单。
// 数据大小可以是一个参考项。
// 默认行为为不存储，否则可能导致新用户的磁盘灾难。
// @id 目标条目ID
// @size 目标条目数据大小
func (p *Ploys) Want(id []byte, size int) bool {
	// 白名单优先
	if p.matched(p.whites, id) {
		return true
	}
	// 黑名单次之
	if p.matched(p.blacks, id) {
		return false
	}
	// 最后为策略脚本判断
	if p.script == nil {
		Log.Println("[Warning] lack of ploy scripts.")
		return false
	}
	return p.script.Passed(id, size)
}

// 匹配性测试。
// 会记录出错信息到日志。
// @list 匹配式集合
// @id 目标ID
func (p *Ploys) matched(list map[string]struct{}, id []byte) bool {
	for pat := range list {
		matched, err := regexp.Match(pat, id)

		if err != nil {
			Log.Println("[Error]", err)
		}
		if matched {
			return true
		}
	}
	return false
}
