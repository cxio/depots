# depots 详细设计

## 概要

### 数据检索

1. 区块链应用向驿站请求目标数据，传递服务名称和数据标识作为定位，驿站收到请求后向内部的目标服务查询数据。
2. 内部服务根据数据标识查询数据，如果没有找到，根据自身的配置策略，向外请求数据或只是简单地告知查询结果。
3. 感知数据的紧缺性，根据配置向内部的微服务提供存储建议。


### 数据写入

1. 写入数据的请求由应用端发起，提供服务名称和数据标识，驿站向内部的目标服务传递写入请求。
2. 目标服务根据数据标识检查数据是否已经存在，如果存在则忽略，否则根据自己的配置策略决定是否存储或者忽略。
3. 如果决定存储，主动发起数据请求，从充当种子的应用节点处获取实际数据。

> **注：**<br>
> 如果为新数据，驿站本身也可配置为主动请求并缓存，而不管内部微服务的情况。这是一个可能的优化。


### 四种数据行为

1. **给**：只读输出，向应用提供数据。
2. **存**：对内写入，向应用提供存储服务，具体行为由内部微服务自己决定。
3. **要**：数据获取，向其它驿站或应用本身请求数据，实施存储计划或数据补充。通常在应用请求发现无数据时触发。
4. **转**：消息转播。对数据的请求流程消息包进行转播。



## 数据请求流程

> **前提：**
> 节点需要知道自身NAT的类型。这借助于公共STUN（findings）服务。


### 四个阶段

1. **数据询问-广播**：一对多逐级扩散，适时终止。
2. **联系回复-传递**：原始线路回传，多对一逐层消减（取2-3个最先收到的回应）。
3. **请求确认-传递**：特定目标线路传递。专属单线路，可能同时多条（冗余）。
4. **建立连接-数据**：与拥有数据的节点建立连接，获取数据。

转播与回复由节点检查自身有无目标数据来体现。有则回复，无则转播询问。


### 数据包类型

1. **询问**（1）。询问者发起的询问数据包。
2. **回复**（2）。拥有数据的节点发回的连系信息包。
3. **确认**（3）。原询问者确认需要目标数据时发送的确认包。
4. **探测**（0）。简单包，单向探测数据的存在性：存在即停止，否则转播。无回复/确认逻辑。



## 数据包规范

**下面代码的格式约定：**

```
(n)  占用字节数，bytes
[n]  占用比特位数，bits
 v]  当前比特序位，bit-position
```


### 1. 数据询问

节点如果需要目标数据，可构造询问包向网络发起数据询问。出于隐私保护，不附带询问者的身份或位置信息。


#### 询问包

```go
[4]     数据包类型。询问包，值1。
[4]     请求跳数累计。上限值15，非零起跳数可以实现一定程度的隐私保护。
(8)     查询标识ID。8字节随机整数，中转节点存储用于辨识当前请求，避免重复转播。
(32)    公钥携带。用于回复节点加密连系信息回应，加密可保证仅有询问者可以查看连系信息。
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
[4]     自身NAT类型。
        1) `Pub0/Public`：公共域节点。
        2) `Pub1/Public@UPnP`：准公共域节点。
        3) `FullC/Full Cone`：完全圆锥型节点。
        4) `RC/Restricted Cone`：受限圆锥型节点。
        5) `P-RC/Port Restricted Cone`：端口受限圆锥型节点。
        6) `Sym/Symmetric NAT`：NAT对称型节点。
[4]     （未用）
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
(2)     目标数据辩识。已知的数据类型，最多支持 `255/255` 两层定位。如：
        0/~ 系统保留。
        1/~ 普通档案数据。可能按文档哈希检索，由子层定义。
        2/1 区块链：区块数据。
        2/2 区块链：交易数据。
        ...
        注：上层的大分类依广泛共识来确定，子层则自便，依其自身内部的约定。

(n)     目标数据索引。根据类型不同，长度也不一样。
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
```


#### 转播包

节点检查自身是否拥有目标数据，若没有，记录询问包的查询标识ID，将询问包内的**跳数加一**后继续转播。
若有，则检查彼此NAT类型并决定是否创建回复。回复的连系信息包含了自身的IP地址、端口号和NAT类型等，连系信息会用询问者的公钥加密。

> **注：**
> NAT连接关系参见：[findings/docs/stunx.md](https://github.com/cxio/findings/docs/stunx.md) 打洞与连接部分。


### 2. 联系回复

询问包的转播过程中，节点会以查询标识ID为键记住询问/转播者，这样回复包就可以按来源路径原路返回了。
原路返回是一种必要的策略，它可以让询问者不必公开自己的连系地址，同时还可以有效地将可能十分庞大的回复数量逐层消减，恢复为正常数量的数据流。


#### 回复包

```go
[4]     数据包类型。回复包，值2。
[4]     （未用）
(8)     查询标识ID。复制询问包相同字段数据。
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
注：以下信息已用询问者公钥加密！
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
(32)    回复者公钥。用于询问者加密确认包连系信息。
[4]     跳数累计值。即询问/转播包里的跳数值，可用于距离评估。
[4]     数据源NAT类型。同上说明，UDP适用。
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
[4]     连接协议。
        - TCP 协议。数据源需为开放服务类型，否则置0。
        - DCP 协议。UDP类型可靠传输，适用于打洞。
        注：TCP和DCP可能同时置位，由询问者自己选择何种服务。
[2]     TCP数据源。可选
        - IPv4 地址标志位。置位表示后续首个地址为IPv4地址。
        - IPv6 地址标志位。
        注：后续地址应按此处的配置顺序排列。
[2]     DCP数据源。可选。
        - IPv4 地址标志位。
        - IPv6 地址标志位。
        注：后续两种协议支持的地址合并按顺序排列。
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
(n...)  数据源地址序列。按前面的配置顺序排列。
        格式：(IP+Port)...
        注：IP与端口紧邻为一组，端口固定2字节长度。
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
```


#### 确认路径

连系回复的回传过程中，如果上层节点接收到同一询问的多个返回，会选择其中的2-3个回复包回传。
同时，上层节点还会记住选择了那几个下层节点的回复（以查询标识ID为键），这样，当原始询问者需要确认时，就可以沿着这条路径广播。这就是确认路径。


### 3. 请求确认

询问者收到回复信息包后，可以：

1. 如果数据源为开放型（Pub0/Pub1/FullC），则直接连接请求数据。
2. 否则构造确认信息包，按**确认路径**原路广播出去。


#### 确认包

```go
[4]     数据包类型。确认包，值3。
[4]     （未用）
(8)     查询标识ID。原始询问包内相同值。
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
注：以下信息已用回复者公钥加密！
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
(4)     连系标识。随机值，用于连接时的身份辨识。
(32)    数据传输密钥。用于传输数据的对称加密（高效）。
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
[2]     请求类型。
        - 请求对方打洞。
        - 请求连入（自己一端已打洞）。
        注：如果自身是对称型NAT，则为请求打洞，否则通常为请求连入。
[2]     自身公网IP类型。
        - IPv4 地址。置位表示确认。
        - IPv6 地址。同上。
[4]     （未用）
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
(n...)  自身公网地址（格式同前）。
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
```


### 4. 建立连接

与拥有目标数据的节点直接建立连接，获取所需数据。P2P逻辑下通常有多个节点符合要求，建立多个连接同时获取。



## 附：数据索引结构

数据需要分片传输以便于即时校验，所以一个文件的数据会按某一固定大小的尺寸划分并创建索引，索引就是每一个分片的哈希汇总。这样就存在两个根哈希：文件数据本身的哈希（文档ID）和传输所需要的索引数据的哈希（校验ID）。

分片本身不宜太大（512KB ~ 2MB），所以一个大文件的索引数据就不小，二叉的默克尔树在内存模型上耗费稍大（索引数据的一倍），所以这里采用**四元链哈希树**来代替。哈希算法采用256位（32字节长），索引结构：`(8)+(32) + (32)(32)(32) ...(8)`。

`(8)` 8字节定义版本号和分片大小以及分片数量。

```go
- [16]  版本号（0-65535）。
- [24]  分片大小，最大支持到16MB。
- [24]  分片数量，最多支持到16M。
  // 附：
  // 每哈希32字节，最多分片数量下索引文件512MB（16MB*32）。
  // 分片大小和数量共48位，最大支持单文件256TB数据的分片索引创建。
  // 分片大小可定义会让索引文件不确定（校验ID可变），这可以增强数据检索的抗干扰性。
```

`(32) + (32)(32)(32) ...(8)` 为各哈希值序列和文件自身的校验码。

```go
(32) 各分片哈希值序列按四元链哈希树结构计算的根哈希，即校验ID。
 +
(32)(32)(32)... 各分片的哈希值序列。
 +
(8) 索引文件自身（除当前8字节）的CRC64校验码。
```


### 文档ID的优化

文档ID是数据的哈希运算结果，但计算一个大文件的哈希摘要是费时的。为了充分利用CPU的并行能力，我们对文档ID作一个变通的定义：**文档ID是数据按 `8MB` 分片后，各分片哈希汇总后的哈希**。也即：文档的校验依然有分片逻辑，但这个分片是固定大小的，并且无树形结构（平级串联）。

`8MB` 可能是一个恰当的值，这个尺寸下大部分MP3音乐文件和数码照片都不用分片计算，文件本身的哈希就是文档ID。



## 开发注记

1. 如果为请求连入：发送确认包后立即对目标打洞。
2. 如果为请求打洞：发送确认包后即可尝试连接。每隔3秒发送一个包，最长持续90秒。

- 数据询问是一对多的广播，因此应当有一个询问频率的约束。如对相同数据的再次询问间隔时间可能为10秒。
- 如果客户端的多次询问没有结果，可以适当更新连接池里的目标节点然后再重新询问。数据可能是一个大文件，可以分片询问。
