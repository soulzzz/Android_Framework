## 1 Davik进程、linux进程、线程之间的区别 ?

#### Linux进程：

1. Linux 进程，它有独立的内核堆栈和独立的存储空间，它是操作系统中资源分配和调度的最小单位。
2. Linux 操作系统会以进程为单位，分配系统资源，给程序进行调度。
3. Linux 操作系统在执行一个程序时，它会创建一个进程，来执行应用程序，并3且伴随着资源的分配和释放。

#### Davik进程：

1. Dalvik 虚拟机运行在 Linux 操作系统之上。
2. Davik 进程就是 Linux 操作系统中的一个进程，属于 linux 进程。
3. 每个 Android 应用程序进程都有一个 Dalvik 虚拟机实例。这样做得好处是Android 应用程序进程之间不会互相影响，也就是说，一个 Android 应用程序进程的意外终止，不会影响到其他的应用程序进程的正常运行。

#### 进程和线程的区别:

1. 一个程序至少有一个进程,一个进程至少有一个线程
2. 线程的划分尺度小于进程，使得多线程程序的并发性高。·
3. 进程在执行过程中拥有独立的内存单元，而多个线程共享内存(同属一个进程).从而极大地提高了程序的运行效率。
4.  每个独立的进程有·个程序运行的入口、顺序执行序列和程序的出口。但是线程不能够独立执行，必须依存在应用程序中，由应用程序提供多个线程执行控制。
5. 从逻辑角度来看，多线程的意义在于一个应用程序中，有多个执行部分可以同时执行。但操作系统并没有将多个线程看做多个独立的应用，来实现进程的调度和管理以及资源分配。这就是进程和线程的重要区别。

## Android 进程间通信:

#### aidl:

AIDL:(Android Interface definition language 的缩写)它是一种android 内部进程通信接口的描述语言，通过它我们可以定义进程间的通信接口.

AIDL 进程间通讯的原理:
通过编写 aidl 文件来定义进程间通信接口。编译后会自动生成响应的java 文件。服务器将接口的具体实现写在 Stub 中，用 iBinder 对象传递给客户端，客户端 bindService 的时候，用 aslnterface 的形式将 iBinder 还原成接口，再调用其接口中的方法来实现通信。

https://www.jianshu.com/p/29999c1a93cd

#### Messenger: 

Messenger 是基于AIDL 实现的。AIDL 使服务器可以并行处理，而 Messenger 封装了 AIDL之后只能串行运行，所以Messenger一般用作消息传递。

X别 Messenger 和 Message。.
Message 是消息，承载了要传递的数据。Messenger 是信使，可以发送消息。并且 Messenger 对象可以通过 getBinder 方法获取一个 Ibinder 对象。

Messenger 实现原理:
服务端(被动方)提供一个 Service 来处理客户端(主动方)连接,维护一个 Handler来创建 Messenger，在onBind 时返回 Messenger 的 binder。双方用 Messenger 来发送数据，用 Handler 来处理数据。Messenger 处理数据靠 Handler，所以是串行的，也就是说，Handler 接到多个 message 时，就要排队依次处理。

使用Messenger 实现进程间通信方法如下:首先A应用提供一个 Service，创建一个 Messenger 对象，在 onBinder 方法里返回 messenger.getBinder()生成的IBinder 对象;然后在B应用绑定该 Service，在 ServiceConnection 的 onServiceConnected 方法获取到IBinder 对象;

然后在 B 应用绑定该 Service，在 ServiceConnection 的 onServiceConnected 方法获取到IBinder 对象;最后在 B应用使用获取到的 binder 对象构造出一个新的Messenger 对象，使用该 Messenger 对象的 send 方法发送的 Message 数据，都将被 Service 里的Messenger 对象 handlerMessage 方法接收到。

https://zhuanlan.zhihu.com/p/618024619

#### ContentProvider

## Android内存泄漏

内存泄露是指保存了不可能再被访问的变量引用，导致垃圾回收器无法回收内存
也就是说:
在 Java 中有些对象的生命周期是有限的，当它们完成了特定的逻辑后将会被垃圾回收:但是，如果在对象的生命周期本来该被垃圾回收时这个对象还被别的对象所持有引用，那就会导致内存泄漏

## Android内存溢出

内存溢出是指虚拟机内存耗尽，无法为新对象分配内存，导致应用崩溃。典型的情况为加载多张大图，导致内存耗尽。

当某个界面存在内存泄露，反复进入该界面，将导致一直有新对象创建但是无法回收，最终内存耗尽，产生内存溢出。

# 2.Android LanuchMode及Intent 启动时FLAG详解

## LaunchMode

Standard：默认值，启动Activity都会重新创建一个Activity的实例进行入栈。此时Activity可能存在多个实例。

SingleTop：当Activity处于栈顶时，再启动此Activity，不会重新创建实例入栈，而是会使用已存在的实例。

SingleTask:与singleTop模式相似，只不过singleTop模式是只是针对栈顶的元素，而singleTask模式下，如果task栈内存在目标Activity实例，则：

1. 将task内的对应Activity实例之上的所有Activity弹出栈。
2. 将对应Activity置于栈顶，获得焦点。

SingleInstance：：单实例模式。是一种加强的singleTask模式，它除了具有singleTask模式的所有特性以为，还加强了一点：具有此种模式的activity只能单独地位于一个任务栈中

## Flag

FLAG_ACTIVITY_BROUGHT_TO_FRONT：如果activity在task存在，拿到最顶端,不会启动新的Activity

FLAG_ACTIVITY_CLEAR_TOP:如果activity在task存在，将Activity之上的所有Activity结束掉 `singleTask`默认具有此标记位的效果。

FLAG_ACTIVITY_NEW_TASK:默认的跳转类型,将Activity放到一个新的Task中 和 `singleTask`一样。

FLAG_ACTIVITY_SINGLE_TOP:如果活动的实例已存在于当前任务的顶部,则系统通过调用其onNewIntent()方法将意图路由到该实例 跟`launchMode`中的`singleTop`一样。

# 3.LayoutInflater

其最终实现只有LayoutInflayer.inflate(ResId,Root,AttachToRoot)：View

第一个参数Xml ID

第二个参数是父容器，不为空指定后第一个参数的xml的根view的宽高magin才有实现。为空则宽高无效。

第三个参数是是否直接加到父容器中，不加的话后续可以通过Root.addView()添加inflate出来的view。

# 4.自定义View

https://wangzhengyi.blog.csdn.net/article/details/49619773?spm=1001.2101.3001.6650.4&utm_medium=distribute.pc_relevant.none-task-blog-2%7Edefault%7EBlogCommendFromBaidu%7ERate-4-49619773-blog-78181578.235%5Ev32%5Epc_relevant_default_base&depth_1-utm_source=distribute.pc_relevant.none-task-blog-2%7Edefault%7EBlogCommendFromBaidu%7ERate-4-49619773-blog-78181578.235%5Ev32%5Epc_relevant_default_base&utm_relevant_index=8

```
 constructor(context: Context) : super(context) {
        init(null, 0)
    }

    constructor(context: Context, attrs: AttributeSet) : super(context, attrs) {
        init(attrs, 0)
    }
	//第三个参数 是通过Theme指定
    constructor(context: Context, attrs: AttributeSet, defStyle: Int) : super(
        context,
        attrs,
        defStyle
    ) {
        init(attrs, defStyle)
    }
```

# 5. Java 同步机制

同步机制有两种方法 ：

1.synchronized  关键字

```
public synchronized void synchronizedMethod() {
    // synchronized 方法体
}

public void synchronizedBlock(Object lock) {
    synchronized (lock) {
        // synchronized 代码块
    }
}

```

2.Lock接口

```
Lock lock = new ReentrantLock();

public void lockMethod() {
    lock.lock();
    try {
        // 加锁代码块
    } finally {
        lock.unlock();
    }
}
lock.lock();
lock.trylock(); 获取不到救释放 可以设置超时参数
lock.lockInterruptibly() 阻塞时可以被打断
还有通过条件变量  控制的 await() 和 signal() https://blog.csdn.net/ZSA222/article/details/123433746 
```

除了以上两种同步机制之外，Java 还提供了一些并发包（如 ConcurrentHashMap、AtomicInteger、CountDownLatch 等）来实现多线程环境下的数据访问安全。

# 6.GC

https://blog.csdn.net/Welcome_Word/article/details/124051691

垃圾回收一般需要暂停所有线程的执行，叫stop-the-world。GC优化基本就是减少暂停次数和暂停时间。

一、回收哪里的垃圾
JVM的内存大致分为5个区，程序计数器，虚拟机栈，本地方法栈，堆，方法区。

程序计数器
顾名思义跟PC寄存器作用类似，每个线程独立存在，生命周期与线程一致。指示当前执行的方法，内存很小，忽略不计，没有垃圾。

虚拟机栈
栈空间，每个线程独立存在，保存方法参数或者方法内对象的引用。生命周期结束，比如方法执行完毕后内存会被释放，所以不需要垃圾管理。

本地方法栈
与虚拟机栈类似，对应native方法。不需要垃圾管理。

堆
对象的实际存储区域，比如在方法内new一个局部变量，在堆开辟内存，引用保存在虚拟机栈。也是垃圾管理的最主要的区域。

方法区
class文件和常量（JDK7开始字符串常量池在堆区）存储区域，属于垃圾管理范围

![在这里插入图片描述](https://img-blog.csdnimg.cn/679d774083b14fe395fe53f174a63fec.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBAemt5Q29kZXI=,size_20,color_FFFFFF,t_70,g_se,x_16)

## CMS （Android4.4到Android8的默认收集器）

```
一个老年代收集器，全称 Concurrent Low Pause Collector（也有说Concurrent Mark Sweep），是JDK1.4后期开始引用的新GC收集器，在JDK1.5、1.6中得到了进一步的改进。它是对于响应时间的重要性需求大于吞吐量要求的收集器。对于要求服务器响应速度高的情况下，使用CMS非常合适。
CMS的一大特点，就是用两次短暂的暂停来代替串行或并行标记整理算法时候的长暂停。
使用算法：标记 - 清理
CMS的执行过程如下：
· 初始标记（STW initial mark）
在这个阶段，需要虚拟机停顿正在执行的应用线程，官方的叫法STW（Stop Tow World）。这个过程从根对象扫描直接关联的对象，并作标记。这个过程会很快的完成。
· 并发标记（Concurrent marking）
这个阶段紧随初始标记阶段，在“初始标记”的基础上继续向下追溯标记。注意这里是并发标记，表示用户线程可以和GC线程一起并发执行，这个阶段不会暂停用户的线程哦。
· 并发预清理（Concurrent precleaning）
这个阶段任然是并发的，JVM查找正在执行“并发标记”阶段时候进入老年代的对象（可能这时会有对象从新生代晋升到老年代，或被分配到老年代）。通过重新扫描，减少在一个阶段“重新标记”的工作，因为下一阶段会STW。
· 重新标记（STW remark）
这个阶段会再次暂停正在执行的应用线程，重新重根对象开始查找并标记并发阶段遗漏的对象（在并发标记阶段结束后对象状态的更新导致），并处理对象关联。这一次耗时会比“初始标记”更长，并且这个阶段可以并行标记。
· 并发清理（Concurrent sweeping）
这个阶段是并发的，应用线程和GC清除线程可以一起并发执行。
· 并发重置（Concurrent reset）
这个阶段任然是并发的，重置CMS收集器的数据结构，等待下一次垃圾回收。
CMS的缺点：
1、内存碎片。由于使用了 标记-清理 算法，导致内存空间中会产生内存碎片。不过CMS收集器做了一些小的优化，就是把未分配的空间汇总成一个列表，当有JVM需要分配内存空间的时候，会搜索这个列表找到符合条件的空间来存储这个对象。但是内存碎片的问题依然存在，如果一个对象需要3块连续的空间来存储，因为内存碎片的原因，寻找不到这样的空间，就会导致Full GC。
2、需要更多的CPU资源。由于使用了并发处理，很多情况下都是GC线程和应用线程并发执行的，这样就需要占用更多的CPU资源，也是牺牲了一定吞吐量的原因。
3、需要更大的堆空间。因为CMS标记阶段应用程序的线程还是执行的，那么就会有堆空间继续分配的问题，为了保障CMS在回收堆空间之前还有空间分配给新加入的对象，必须预留一部分空间。CMS默认在老年代空间使用68%时候启动垃圾回收。可以通过-XX:CMSinitiatingOccupancyFraction=n来设置这个阀值。

CMS 在Android的应用中，当对象分配因碎片而失败或者应用进入后台后会执行压缩，解决内存碎片问题。

```

## CC（Concurrent Copying）

Android8开始默认垃圾收集器

```
CC 支持使用名为“RegionTLAB”的触碰指针分配器。此分配器可以向每个应用线程分配一个线程本地分配缓冲区 (TLAB)，这样，应用线程只需触碰“栈顶”指针，而无需任何同步操作，即可从其 TLAB 中将对象分配出去。
CC 通过在不暂停应用线程的情况下并发复制对象来执行堆碎片整理。这是在读取屏障的帮助下实现的，读取屏障会拦截来自堆的引用读取，无需应用开发者进行任何干预。
GC 只有一次很短的暂停，对于堆大小而言，该次暂停在时间上是一个常量。
在 Android 10 及更高版本中，CC 会扩展为分代 GC。它支持轻松回收存留期较短的对象，这类对象通常很快便会无法访问。这有助于提高 GC 吞吐量，并显著延迟执行全堆 GC 的需要。
```

### GC触发时机

https://linus.blog.csdn.net/article/details/108786459?spm=1001.2101.3001.6650.4&utm_medium=distribute.pc_relevant.none-task-blog-2%7Edefault%7ECTRLIST%7ERate-4-108786459-blog-44963135.235%5Ev32%5Epc_relevant_default_base&depth_1-utm_source=distribute.pc_relevant.none-task-blog-2%7Edefault%7ECTRLIST%7ERate-4-108786459-blog-44963135.235%5Ev32%5Epc_relevant_default_base&utm_relevant_index=9

```
25 // What caused the GC?
26 enum GcCause {
27   // Invalid GC cause used as a placeholder.
28   kGcCauseNone,
29   // GC triggered by a failed allocation. Thread doing allocation is blocked waiting for GC before
30   // retrying allocation.
31   kGcCauseForAlloc,
32   // A background GC trying to ensure there is free memory ahead of allocations.
33   kGcCauseBackground,
34   // An explicit System.gc() call.
35   kGcCauseExplicit,
36   // GC triggered for a native allocation when NativeAllocationGcWatermark is exceeded.
37   // (This may be a blocking GC depending on whether we run a non-concurrent collector).
38   kGcCauseForNativeAlloc,
39   // GC triggered for a collector transition.
40   kGcCauseCollectorTransition,
41   // Not a real GC cause, used when we disable moving GC (currently for GetPrimitiveArrayCritical).
42   kGcCauseDisableMovingGc,
43   // Not a real GC cause, used when we trim the heap.
44   kGcCauseTrim,
45   // Not a real GC cause, used to implement exclusion between GC and instrumentation.
46   kGcCauseInstrumentation,
47   // Not a real GC cause, used to add or remove app image spaces.
48   kGcCauseAddRemoveAppImageSpace,
49   // Not a real GC cause, used to implement exclusion between GC and debugger.
50   kGcCauseDebugger,
51   // GC triggered for background transition when both foreground and background collector are CMS.
52   kGcCauseHomogeneousSpaceCompact,
53   // Class linker cause, used to guard filling art methods with special values.
54   kGcCauseClassLinker,
55   // Not a real GC cause, used to implement exclusion between code cache metadata and GC.
56   kGcCauseJitCodeCache,
57   // Not a real GC cause, used to add or remove system-weak holders.
58   kGcCauseAddRemoveSystemWeakHolder,
59   // Not a real GC cause, used to prevent hprof running in the middle of GC.
60   kGcCauseHprof,
61   // Not a real GC cause, used to prevent GetObjectsAllocated running in the middle of GC.
62   kGcCauseGetObjectsAllocated,
63   // GC cause for the profile saver.
64   kGcCauseProfileSaver,
65   // GC cause for running an empty checkpoint.
66   kGcCauseRunEmptyCheckpoint,
67 };

```

根据GcCause可知，可以触发GC的条件还是很多的。对于开发者而言，常见的是其中三种：

GcCauseForAlloc：通过new分配新对象时，堆中剩余空间(普通应用默认上限为256M，声明largeHeap的应用为512M)不足，因此需要先进行GC。这种情况会导致当前线程阻塞。

GcCauseExplicit：当应用调用系统API System.gc()时，会产生一次GC动作。

GcCauseBackground：后台GC，这里的“后台”并不是指应用切到后台才会执行的GC，而是GC在运行时基本不会影响其他线程的执行，所以也可以理解为并发GC。相比于前两种GC，后台GC出现的更多也更加隐秘，因此值得详细介绍。下文讲述的全是这种GC。

Java堆的实际大小起起伏伏，影响的因素无非是分配和回收。分配的过程是离散且频繁的，它来自于不同的工作线程，而且可能每次只分配一小块区域。回收的过程则是统一且偶发的，它由HeapTaskDaemon线程执行，在GC的多个阶段中都采用并发算法，因此不会暂停工作线程(实际上会暂停很短一段时间)


当我们在Java代码中通过new分配对象时，虚拟机会调用AllocObjectWithAllocator来执行真实的分配。在每一次成功分配Java对象后，都会去检测是否需要进行下一次GC，这就是GcCauseBackground GC的触发时机。

# 7 Fork新进程启动应用

![img](https://upload-images.jianshu.io/upload_images/4264767-df784487cd0a56b9.png?imageMogr2/auto-orient/strip|imageView2/2/w/960/format/webp)

![img](https://upload-images.jianshu.io/upload_images/4264767-d20633f05e06df67.png?imageMogr2/auto-orient/strip|imageView2/2/w/1200/format/webp)
