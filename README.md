# 数据驿站服务（depots）

## 前言

在传统的P2P网络里，相同应用的节点间相互连接，交互彼此需要或拥有的数据，不同应用之间是隔离的，即便操作的是同一份数据。

数据驿站服务试图在不同的应用系统之间抽象出统一的接口，专门操作数据本身，最大限度地剥离应用的负载，同时也提高效率。实际上，这样的数据服务可以成为P2P网络的通用数据层，如果把网络比喻为一台计算机，这一数据层就类似于文件系统。

数据驿站是一个「壳」，管理数据在全网的流通和缓存，内部由具体的微服务实际操作数据（archives、blockqs）。基本上，这可以理解为一个内含数据仓库的数据中转站：数据是变动的，增加、减少、临时存储、或某种处理等。

数据驿站之间相互连接组成P2P网络，创建出一个自由交换的数据流动层，因而支持开放式的数据存取服务。


## 紧缺性感知机制

P2P网络节点对数据的请求是通过广播查询，没有目标数据的节点会转播请求，拥有数据的节点则回应而不再转播。如果设计请求每转播一次就跳数加一，则通过跳数的大小，节点就可以感知请求广播的距离。距离越远说明数据越紧缺，这可以促使节点补充存储紧缺的数据。

驿站之间的这种协作存储，通常会拥有较大的冗余度，但无法100％保证数据的完备性，如果一些数据请求很少，则可能在较长的时间段内慢慢消失。因此，我们需要设计一种措施来保证数据请求的全面性。


### 数据心跳

自然的紧缺性感知并不完全可靠。有些数据的用户很少或使用率极低，这些数据的请求就会很少，它们可能被慢慢遗忘、清理、最后丢失。

数据心跳就是执行全面性探知的一种机制，它由某种公益节点对稀有的数据发出一种探查请求。探查不是请求数据本身，它包含了一个标记说明只是数据查询，拥有数据的节点无需回应，没有数据的节点正常转播。于是这些稀有数据的紧缺性就可以被察觉到了。

数据索引（ID）都已存在于区块链上，所以探查节点按索引间断发出探测请求即可。这些探测节点被称为心跳节点，理论上应该在地理位置上均衡分布，不需要太多。


### 附：数据ID与服务标识

数据ID是数据的哈希摘要，用于唯一地标识一个数据，但事实上，请求标识可以不止是数据ID，它还可以是服务ID，客户机查询该标识建立联系获得服务，这在外观上与数据ID没有区别。

传统的**客户机/服务器**网络通过域名寻址查找服务，而这里则是以随机的ID标识，通过P2P网络查询服务。显然，这更隐秘、灵活，甚至更有扩展性。


## 数据站群

数据驿站不必是一个实体的概念，如果允许任意数据服务节点声明同一个收益公钥（地址），实际上这就创建出一个虚拟的「数据驿站」了。因为声明共同的收益地址，所以这个地址被认可的范围会更广，这会提升兑奖的确认数（兑奖比例）。


### 开放评估

数据站群的管理者需要评估成员节点的服务绩效，为奖励的分发提供依据。因为数据服务是端对端的，服务节点直接给请求者提供数据，所以嵌入第三方的管理职能会是一个问题。这里提供一个简单的解决思路。


#### 协议补充

数据服务节点在提供数据的同时，需要向对方公布自己的收益地址，以此来接收当前区块链的代币奖励。这里，我们增加一个可选的字段：身份ID。

身份ID的用途是服务节点在站群中标注自己，这样站群的管理者就可以向自己发送奖励。


#### 匿名探测

不需要任何管理措施，管理者可以像普通客户一样向网络请求数据，如果对方公布的收益地址与本群的相同，即为站群成员，此时记录其身份ID，并对其服务进行评估。

探测是匿名的，难以作弊，因为它不知道何时可以撒谎。


#### 开放性

数据站群的信息（收益地址）是公开的，这样才能方便地吸引离散的自由节点加入。因为收益地址公开，如果你愿意，通过匿名探测的方式，实际上你可以探测出任何一个站群的成员有哪些。也因此，你可以评估一个数据站群的奖励分配的合理性。

这种开放监督的可能性，可以约束站群管理者的行为。


### 随机缓存

敏感的数据可能被屏蔽，小众的数据可能遗失。所以从全网整体存储的合理分布上看，站群成员的缓存数据应当是随机性的。

站群成员随机的数据策略还可以增强数据源的隐匿性，因为数据几乎随手可及，攻击者难以追溯它的完整存储源。


## 无效数据

存储的数据是离散的，但它们都基于区块中交易里的附件ID（作为索引），因此不在区块链上标记的数据是无效的。

发动对无效数据的请求可能成为一种攻击，如果普遍的节点都不去分辨的话，这会导致**补充存储**的请求泛滥。

对于一个普通的数据服务节点来说，分辨数据是否有效有一定难度。要么它需要集成一个有效ID的集合，要么发送数据心跳的节点拥有权威性（公认的签名）。
