--[[
存档类（A: archives）
    用户存储策略函数定制。
    作者：风尘
    邮箱：chainx.zh@gmail.com 2025.01.06

规范：
用户需要定义一个ploy函数，返回一个布尔值，表示是否执行当前存储。
    function ploy(hash, size) bool
    - hash:string 目标ID（字节序列）。
    - size:number 数据的大小。

提示：
这里仅为一个简单示例。实际情况下，
用户可能会需要存取内部的数据库来衡量，或者有其它考虑。
--]]

function ploy(hash, size)
    -- 范围超限。
    if size == 0 or size > 2^32 then
        return false
    end
    -- 计算哈希序列各字节之和。
    local sum = 0
    for i = 1, 32 do
        sum = sum + string.byte(hash, i)
    end
    -- 大于半数有效。
    return sum > 32 * 128
end
