--[[
存档类（A: archives）
    作者：尘风
    邮箱：chainx.zh@gmail.com
    日期：2025.01.06

接口：
返回的布尔值（true|false）表示是否存储。
    function ploy(hash, size) bool
        - hash:string 目标ID（bytes）。
        - size:number 数据大小（字节数）。
--]]

-- 示例：
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
