## Shamir Secret Sharing 使用说明



### 更新记录

---

v1.0

* 交付数盾使用

v1.1

* 增加数个丢失的返回值/参数检查
* 允许使用 256 bit 密钥

v1.2

* 更新全局变量y的释放方式，避免用户在调用recover_secret后，

  没有第二次调用recover_secret，造成内存泄露。





### 前提条件

---

OpenSSL 1.1.1 (1.1.1之前版本未进行测试)

C编译器



### 基本类型

---

用户主要与shm_key_share_t链表进行交互，此类型包含了一个分量密钥的X, Y坐标、公共参数P、公共参数N、编码标识B以及下一个分量的地址。

* X, Y ：分量密钥的X、Y坐标
* P ：密钥的有限域
* N ：最少需要的分量密钥个数
* B ：分量密钥X、Y、P的编码，2代表二进制，16代表16进制，etc.
* next ：下一个分量密钥的地址，最后一个分量密钥指向NULL。

以上元素均可使用shm_key_share\_STH 和 shm_key_share_set\_STH 进行取值或设置。



### 调用方式

---



1. 生成新的密钥组

   ​	用户应用过shm_key_share_new分配内存空间，并通过shm_keygen获取分量密钥。

   ​	security_lv表示原始密钥的密钥长度，密钥所在有限域永远比密钥长度多1bit，如 GF(2<sup>129</sup>)， GF(2<sup>257</sup>)。

   ​	同时用户需要提供重组原始密钥需要的分量个数min，以及本次产生非分量个数max。

   ​	当用户提供原始密钥secret时，keygen将使用用户提供的secret，否则将自动产生原始密钥。用户提供的原始密钥应该满足BN_RAND_TOP_ONE。

2. 通过已有分量获取原始密钥

   ​	用户可以通过shm_recover_secret获取原始密钥。先通过传入shm_recover_secret(NULL, &len, ks, min)

   获得secret的长度，然后通过shm_recover_secret(secret, &len, NULL, 0)获得原始密钥secret。

   ​	

3. 通过已有分量获取更多分量

   ​	用户可以通过shm_create_more_key_share创建匹配已有分量的更多密钥。



注意：

​	用户在调用任何函数后，应该通过shm_cleanup清理分量密钥链表，(3)应该调用两次。



### 返回值

---

shm_key_share_new

shm_key_share_next

shm_key_share_x

shm_key_share_y

shm_key_share_p 

返回对应数据的指针，错误时返回NULL。



其它方法均返回int，参照shamir.h中的错误代码定义。



### 其它

---

在编译时使用 -D DEBUG=1测试基本数据GF(1613)。DEBUG=0测试BIGNUM。







