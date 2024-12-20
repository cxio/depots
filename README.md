# 数据驿站服务（depots）

## 前言

在传统的P2P网络里，相同应用的节点间相互连接，交互彼此需要或拥有的数据，不同应用之间是隔离的，即便操作的是同一份数据。

数据驿站服务试图在不同的应用系统之间抽象出统一的接口，专门操作数据本身，最大限度地剥离应用的负载，同时也提高效率。实际上，这样的数据服务可以成为P2P网络的通用数据层，如果把网络比喻为一台计算机，这一数据层就类似于文件系统。

数据驿站只是一个内嵌微服务的「壳」，它管理数据在全网的交互流通和暂存，内部的微服务则实际操作数据（archives、blockqs）。基本上，这可以理解为一个内含数据仓库的数据中转站，数据是变动的：增加、减少、暂存、或某种特别处理等。

数据驿站之间相互连接组成P2P网络，构造出一个自由交互的数据流动层。数据的存储是开放式的。


## 开放式存储

### 数据的紧缺性感知机制

P2P网络节点对数据的请求是通过广播查询，没有目标数据的节点会转播请求，拥有数据的节点则回应而不再转播。如果设计请求每转播一次就跳数加一，则通过跳数的大小，节点就可以感知请求广播的距离。距离越远说明数据越紧缺，这可以促使节点补充存储紧缺的数据。

驿站之间的这种协作存储，通常会拥有较大的冗余度，但无法100％保证数据的完备性，如果一些数据请求很少，则可能在较长的时间段内慢慢消失。因此，我们需要设计一种措施来保证数据请求的全面性。


### 数据心跳

自然的紧缺性感知并不完全可靠。有些数据的用户很少或使用率极低，这些数据的请求就会很少，它们可能被慢慢遗忘、清理、最后丢失。

数据心跳就是执行全面性探知的一种机制，它由某种公益节点对稀有的数据发出一种探查请求。探查不是请求数据本身，它包含了一个标记说明只是数据查询，拥有数据的节点无需回应，没有数据的节点正常转播。于是这些稀有数据的紧缺性就可以被察觉到了。

数据索引（ID）都已存在于区块链上，所以探查节点按索引间断发出探测请求即可。这些探测节点被称为心跳节点，理论上应该在地理位置上均衡分布，不需要太多。


### 数据ID与服务标识

数据ID是数据的哈希摘要，用于唯一地标识一个数据，但事实上，请求标识可以不止是数据ID，它还可以是服务ID，客户机查询该标识建立联系获得服务，这在外观上与数据ID没有区别。

传统的**客户机/服务器**网络通过域名寻址查找服务，而这里则是以随机的ID标识，通过P2P网络查询服务。显然，这更隐秘、灵活，甚至更有扩展性。


## 数据站群

数据驿站不必是一个实体，如果有多个服务节点声明同一个收益地址，实际上就创建出一个虚拟的数据站群了。声明共同的收益地址可以使该地址在更广的范围内被认可，从而提升兑奖比例（确认数）。


### 开放评估

如果创建了数据站群，其管理者需要评估成员节点的服务效率，为分发奖励提供依据。但因为数据服务是端对端的，服务节点直接给请求者提供数据，所以嵌入第三方的管理会是一个问题。

这里提供一个简单的思路：**开放式评估**。


#### 协议补充

数据服务节点在提供数据的同时，需要向对方公布自己的收益地址，以此来接收区块链的代币奖励。这里，我们增加一个可选的字段：**身份ID**。用途是服务节点在站群中标注自己，以便站群管理者向自己发放收益。

身份ID可能由管理者发放，进行中心化管理。也可以是开放的自由加入的模式（去中心化），由用户提供一个自己的收款地址（身份ID）即可。

第三方的区块链应用（或其它支持奖励的普通应用）只会评估收益地址本身，考评地址关联的服务器服务怎么样。身份ID在这里会被简单忽略，它只对数据站群的管理者有意义。


#### 匿名探测

如果采用非中心化的开放式合作，则很难实施管理。

这里，我们采用匿名探测的方式来评估加入节点的工作质量：管理者像普通客户一样向网络请求数据，如果对方公布的收益地址与本群相同，即为站群成员，此时记录其身份ID，并对其服务进行测试评估。

探测是匿名的，难以作弊，因为对方不知道何时是管理者在探测，以提供良好的服务来博取好感。


#### 开放性

数据站群的收益地址通常是公开的，这样方便吸引离散的自由节点加入。

如果收益地址公开，如果你愿意，通过匿名探测的方式，实际上你可以探测出任何一个站群的成员有哪些。也因此，你甚至可能去评估一个数据站群的奖励分配的状况。


### 随机缓存

敏感的数据可能被屏蔽，小众的数据可能遗失。

所以从全网整体存储的合理分布上看，数据节点的缓存数据应当是碎片化离散和随机的才好。

随机的数据还可以增强数据完整源的隐匿性，因为如果某数据触手可及到处都是，攻击者就难以追溯它的最初来源（从而实施攻击）。


## 其它数据

本数据网络是区块链的公共服务系统，用于分离区块链的数据存储，其索引是交易ID或交易中的附件ID。

但是，如果有市场需求，实际上也可以存储其它任意类型的数据，只要有服务器节点愿意存储它们即可。数据在存储和请求中并不会被核验是否属于某个区块链，这种检查既浪费资源也无必要。

> 注：
> 区块链就像数据的全网索引，公益的数据心跳节点是一种优势。
