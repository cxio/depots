# 数据驿站（depots）

## 概要

在传统的数据分享应用里，针对想要的数据，用户可以根据数据的索引ID，从拥有数据的多个节点那里获取。

在这里，拥有数据的用户是零散的，有的用户即便拥有数据，也不一定在线或开启数据分享。用户与用户之间没有关联，分享是一种极其松散的逻辑。对于很多古老的数据，由于缺乏驱动力，很难找到相应的数据节点。这就很难形成一个可靠持久的数据分享网络。

总结原因大概有如下两点：

1. 缺乏利益驱动。久远数据会随着热度的下降，用户不再保存，逐渐淡出分享网络，以至于完全不可再得。
2. 缺乏一种机制。这种机制可以让用户知道哪些数据稀缺，需要存储。这样，自由零散的用户就可以有所选择地存储。

数据驿站就是为这一目的而设计的。

1. 利益驱动：借助于区块链代币的自由**直付**（直接支付）能力，可以对提供数据分享的节点提供收益回报。
2. 感知机制：驿站节点组成网络，提供数据的请求和回复转播，通过转播跳数感知数据的紧缺性，从而为特定数据的存储选择提供参考。

驿站节点组成的网络只提供**数据信号**（请求、回复、侦测）的转播，请求包含了数据的索引，回复包含了数据源节点（或中转节点）的地址。用户可以向网络发送数据询问，获得数据拥有者的回答，然后使用内置集成或第三方的App进行具体的数据传输。

虽然不负责数据本身的传输，但网络提供了数据供需的关键信号，让数据可以在全网级协调和存储，因此有时也会使用*数据网络*来简称。


## 开放式存储

### 数据的紧缺性感知机制

网络节点对数据的请求通过广播查询，没有目标数据的节点会转播请求，拥有数据的节点则回应并不再转播。

如果请求每转播一次就跳数加一，则通过跳数的大小，节点可以感知请求广播的距离。总体上来说，广播的距离越远，说明数据越紧缺。这可以促使部分节点补充存储——这取决于节点的存储策略。

这种协作存储可能会有较大的冗余度，但同时也可能无法100％保证数据的完备性。如果某些数据请求很少，在长时间的*淡忘*下，它们很可能就会慢慢消失。

因此，这需要一种措施，来保证数据请求的广泛性（甚至完备度）。


### 数据心跳

如果有一些节点，可以对广泛的数据索引执行间歇性的请求（其实是一种探测），就可以持续让网络上的节点知道那些数据的存储丰度。这种探测，可以称之为心跳。

数据心跳是由一些公益节点发出的，数据的广度由这些节点来保证。通常来说，它们主要关注那些创建时间较久的数据，或者，如果区块链上有数据的索引，那这些数据就更容易有保障了。

理论上，这些公益节点在地理位置上均衡分布会更好，因为只是简单的探查请求，或许不需要太多。


### 数据ID与服务标识

在数据请求里会有一个数据索引，它通常是数据的ID（数据内容的哈希摘要），但事实上，数据索引也可以不是数据ID，它可以是某种服务的标识：客户端通过查询该标识，获得提供相应服务的节点，然后建立联系。这在外观上，基本上与数据ID很难区分。

传统的网络通过域名寻址查找服务器，这里的ID可以是随机的，显然，这可能更隐秘、灵活一些。


## 数据站群

对数据源服务的奖励，通过数据源向用户提供自己的区块链代币地址来实现。奖励并不必然，但是可能的。某些区块链的实现会特意关注这一点：它们委托驿站&数据网络存储自己的历史区块数据。

数据驿站不必是单个实体，如果多个服务节点声明同一个代币收益地址，实际上就创建了一个虚拟的数据站群（看起来属于某一实体）。声明共同的收益地址可以使该地址在更广的范围内可见，因此也更容易被认可，从而提升兑奖的可能性（详见 `github.com/cxio/chainx` 项目）。


### 开放评估

如果创建了数据站群，其管理者需要评估成员节点的服务效率，为分发奖励提供依据。但因为数据服务是端对端的，服务节点直接给请求者提供数据，所以嵌入第三方的管理会是一个较为复杂的问题。这里提供一个简单的思路：**开放式评估**。


#### 协议补充

数据服务节点在提供数据的同时，需要向对方公布自己的收益地址，以此来接收区块链的代币奖励。这里，我们增加一个可选的字段：**身份ID**。用途是服务节点在站群中标注自己，以便站群管理者向自己发放收益。

身份ID可能由管理者发放，进行中心化管理。也可以是开放的自由加入的模式（去中心化），由用户提供一个自己的收款地址（身份ID）即可。

第三方的区块链应用或其它支持奖励的应用只会评估收益地址本身（其直接关联服务），身份ID会被简单忽略。身份ID只对数据站群的管理者有意义。


#### 匿名探测

如果采用非中心化的开放式合作，则实施管理是一件比较困难的事。

这里，我们采用匿名探测的方式来评估加入节点的工作质量：管理者像普通客户一样向网络请求数据，如果对方公布的收益地址与本群相同，即为站群成员，此时记录其身份ID，并对其服务进行测试评估。

探测是匿名的，服务节点很难讨好作弊，因为不清楚何时是管理者，何时是实际的用户。


#### 开放性

数据站群的收益地址通常是公开的，这样方便吸引离散的自由节点加入。

如果收益地址公开，只要你愿意，通过匿名探测的方式，实际上你可以评估任何一个站群，甚至了解开放式站群的奖励分配是否公允。


### 数据源隐私

敏感的数据可能遭遇屏蔽阻断攻击，或者数据源被定位。

如果需要增强数据源的安全性和隐私保护，可以借助于中转网设计（详见 `design.md`）。数据源并不回复自身的地址，而是随机的远端中转节点的信息。


## 其它数据

本数据网络主要是服务于区块链的公共存储，数据索引是交易中的附件ID（`Archives`）或区块ID（`Blockqs`）等。

但是如果市场有需求，此数据网络也是通用的——只要有服务节点愿意存储即可。存储节点并不会核验数据ID的起源，但数据上链应该更容易保证其完备性。
