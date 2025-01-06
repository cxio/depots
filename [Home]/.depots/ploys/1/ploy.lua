--[[
区块链（B: blockqs）
    区块链策略函数定制。
    作者：风尘
    邮箱：chainx.zh@gmail.com 2025.01.06

规范：
用户需要定义一个ploy函数，返回一个布尔值，表示是否执行当前存储。
    function ploy(hash, size) bool
    - hash:string 目标ID（字节序列）。
    - size:number 数据的大小。

提示：
区块链数据在数据网络中仅以区块为单位感知其紧缺性，主要是驿站节点间的同步。
驿站应该只存储自己支持的区块链类型。
--]]

function ploy(hash, size)
    return true -- 待编码。
end
