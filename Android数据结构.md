# ArrayMap、SparseArray、HashMap区别

## HashMap

```
HashMap内部是使用一个默认容量为16的数组来存储数据的，而数组中每一个元素却又是一个链表的头结点，所以，更准确的来说，HashMap内部存储结构是使用哈希表的拉链结构（数组+链表），这种存储数据的方法叫做拉链法 。如图： 
```

![img](https://img-blog.csdn.net/20160903104526700?watermark/2/text/aHR0cDovL2Jsb2cuY3Nkbi5uZXQv/font/5a6L5L2T/fontsize/400/fill/I0JBQkFCMA==/dissolve/70/gravity/Center)

```
且每一个结点都是Entry类型，那么Entry是什么呢？我们来看看HashMap中Entry的属性：

final K key;
final V value;
final int hash;
HashMapEntry<K, V> next;

从中我们得知Entry存储的内容有key、value、[hash](https://so.csdn.net/so/search?q=hash&spm=1001.2101.3001.7020)值、和next下一个Entry，那么，这些Entry数据是按什么规则进行存储的呢？就是通过计算元素key的hash值，然后对HashMap中数组长度取余得到该元素存储的位置，计算公式为hash(key)%len，比如：假设hash(14)=14,hash(30)=30,hash(46)=46 我们对len取余，得到hash(14)%16=14,hash(30)%16=14，hash(46)%16=14。所以hash值为14的这个元素存储在数组下标为14的位置。

```

![img](https://img-blog.csdn.net/20160903105847219?watermark/2/text/aHR0cDovL2Jsb2cuY3Nkbi5uZXQv/font/5a6L5L2T/fontsize/400/fill/I0JBQkFCMA==/dissolve/70/gravity/Center)

```
从中可以看出，如果有多个元素key的hash值相同的话，后一个元素并不会覆盖上一个元素，而是采取链表的方式，把之后加进来的元素加入链表末尾，从而解决了hash冲突的问题，由此我们知道HashMap中处理hash冲突的方法是链地址法。

在此补充一个知识点，处理hash冲突的方法有以下几种：

1. 开放地址法
2. 再哈希法
3. 链地址法
4. 建立公共溢出区

讲到这里，重点来了，我们知道HashMap中默认的存储大小就是一个容量为16的数组，所以当我们创建出一个HashMap对象时，即使里面没有任何元素，也要分别一块内存空间给它，而且，我们再不断的向HashMap里put数据时，当达到一定的容量限制时（这个容量满足这样的一个关系时候将会扩容：HashMap中的数据量>容量*加载因子，而HashMap中默认的加载因子是0.75），HashMap的空间将会扩大，而且扩大后新的空间一定是原来的2倍，我们可以看put()方法中有这样的一行代码：


int newCapacity = oldCapacity * 2;


所以，只要一满足扩容条件，HashMap的空间将会以2倍的规律进行增大。假如我们有几十万、几百万条数据，那么HashMap要存储完这些数据将要不断的扩容，而且在此过程中也需要不断的做hash运算，这将对我们的内存空间造成很大消耗和浪费，而且HashMap获取数据是通过遍历Entry[]数组来得到对应的元素，在数据量很大时候会比较慢，所以在Android中，HashMap是比较费内存的。



所以我们在一些情况下可以使用SparseArray和ArrayMap来代替HashMap。
```

## ArrayMap:

https://blog.csdn.net/vansbelove/article/details/52422087