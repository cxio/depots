--[[
区块链（B: blockqs）
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

function ploy(hash, size)
    return true -- 待编码。
end
