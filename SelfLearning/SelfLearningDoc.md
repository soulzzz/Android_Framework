# JAVA相关

## 1.数据结构

### ArrayBlockingQueue :有界阻塞队列

​	此队列按照先进先出（FIFO）的原则对元素进行排序。默认情况下不保证访问者公平的访问队列，所谓公平访问队列是指阻塞的所有生产者线程或消费者线程，当队列可用时，可以按照阻塞的先后顺序访问队列，即先阻塞的生产者线程，可以先往队列里插入元素，先阻塞的消费者线程，可以先从队列里获取元素。通常情况下为了保证公平性会降低吞吐量。

|      | 抛出异常 | 特殊值 | 阻塞 | 超时               |
| ---- | -------- | ------ | ---- | ------------------ |
| 插入 | add      | offer  | put  | offer(e,time,unit) |
| 移除 | remove   | poll   | take | poll(time,unit)    |
| 检查 | element  | peek   | X    | X                  |



add(E e)：把 e 加到 BlockingQueue 里，即如果 BlockingQueue 可以容纳，则返回 true，否则报异常 
offer(E e)：表示如果可能的话，将 e 加到 BlockingQueue 里，即如果 BlockingQueue 可以容纳，则返回 true，否则返回 false 
put(E e)：把 e 加到 BlockingQueue 里，如果 BlockQueue 没有空间，则调用此方法的线程被阻断直到 BlockingQueue 里面有空间再继续
poll(time)：取走 BlockingQueue 里排在首位的对象，若不能立即取出，则可以等 time 参数规定的时间,取不到时返回 null 
take()：取走 BlockingQueue 里排在首位的对象，若 BlockingQueue 为空，阻断进入等待状态直到 Blocking 有新的对象被加入为止 
remainingCapacity()：剩余可用的大小。等于初始容量减去当前的 size



### LinkedBlockingQueue:基于链表的阻塞队列



### Stream 流



https://www.runoob.com/java/java8-streams.html

```

public class Boo {
    public static void main(String[] args) {
        // 定义一个集合
        ArrayList<String> list = new ArrayList<>();
        list.add("张三");
        list.add("李四");
        list.add("李四");
        list.add("李四");
        list.add("李四");
        list.add("李四");
        list.add("李四");
 
        //Stream流实现
        list.stream()
                .filter((name) -> name.startsWith("朱婧"))
                .filter((name) -> name.length()==2)
                .forEach((name) -> System.out.println(name));
 
    }
}
```

![CollectionListSet](.\CollectionListSet.png)
---|Collection: 单列集合  
            ---|List: 有存储顺序, 可重复  
                	---|ArrayList:  数组实现, 查找快, 增删慢  
                            由于是数组实现, 在增和删的时候会牵扯到数组  
                                                增容, 以及拷贝元素. 所以慢。数组是可以直接  
                                                按索引查找, 所以查找时较快  
            	    ---|LinkedList: 链表实现, 增删快, 查找慢  
                            由于链表实现, 增加时只要让前一个元素记住自  
                                               己就可以, 删除时让前一个元素记住后一个元  
                                               素, 后一个元素记住前一个元素. 这样的增删效  
                                             率较高但查询时需要一个一个的遍历, 所以效率  
                                                较低  
              	  ---|Vector: 和ArrayList原理相同, 但线程安全, 效率略低  
                             和ArrayList实现方式相同, 但考虑了线程安全问  
                                                题, 所以效率略低  
            ---|Set: 无存储顺序, 不可重复  
                ---|HashSet  
                ---|TreeSet  
                ---|LinkedHashSet  
---| Map: 键值对  
        ---|HashMap  
        ---|TreeMap  
        ---|HashTable  
        ---|LinkedHashMap

## 2.线程池

public ThreadPoolExecutor(int corePoolSize,
                          int maximumPoolSize,
                          long keepAliveTime,
                          TimeUnit unit,
                          BlockingQueue<Runnable> workQueue,
                          ThreadFactory threadFactory,
                          RejectedExecutionHandler handler)

| 参数                     | 含义                             | 解释                                                         |
| ------------------------ | -------------------------------- | ------------------------------------------------------------ |
| corePoolSize             | 线程池中的核心线程数             | 核心线程生命周期无限，即使空闲也不会死亡。                   |
| maximumPoolSize          | 线程池中最大线程数               | 任务队列满了以后当有新任务进来则会增加一个线程来处理新任务，(线程总数 < maximumPoolSize） |
| keepAliveTime            | 闲置超时时间                     | 当线程数大于核心线程数时，经过keepAliveTime时间将会回收非核心线程 |
| unit                     | 超时时间的单位（时/分/秒等）     |                                                              |
| workQueue                | 线程池中的任务队列               | 存放任务(Runnable)的容器                                     |
| threadFactory            | 为线程池提供创建新线程的线程工厂 |                                                              |
| rejectedExecutionHandler | 拒绝策略                         | 新增一个任务到线程池，如果线程池任务队列超过最大值之后,并且已经开启到最大线程数时，默认为抛出ERROR异常n |



# Android相关

## OkHttp

#### Okhttp介绍

Android 在4.4及以上中HttpUrlConnection底层一部分使用Okhttp实现，且HttpClient在Android 6.0 API23 已经移除。



## MediaPlayer

### 生命周期

![MediaPlayerLifeCycle](.\MediaPlayerLifeCycle.png)

```

player.stop();
player.reset();  //To Idle State, 可以直接SetDataSource 进入Initialized State
player.release();  //To  End State


SurfaceView surfaceView = findViewById(R.id.mSurfaceView);
mSurfaceView.getHolder.addCallBack(new MyCallBack());
Class MyCallBack Extends SurfaceHolder.CallBack{
	public void surfaceCreated(SurfaceHolder holder){
	MediaPlayer player = new MediaPlayer();  
    player.setDataSource("/sdcard/test.mp3");
    player.setDisplay(surfaceView.getHolder());
    player.prepare();|| player.prepareAsync();
	}
}
```

## Service

#### 1.startService

onCreate —》onStartCommand —》onStart    ->stopService() ->onDestroy()

#### 2.bindService

onCreate —》onBind —》（onServiceConnected） ->onUnbind() ->onDestroy()

#### 3.start ->bind 

onCreate —》onStartCommand —》onStart —》onBind —》（onServiceConnected）  需要unbindService和stopService同时调用才行。与两者顺序无关

## IntentService

使用Service其本质也是UI线程，需要再Service中开辟新线程执行耗时任务,onbind。

便捷方法就是使用IntentService,其内部已经封装好了。

使用 Service 时总会创建一个线程来执行任务，而不是直接在 Service中执行。这是因为 Service 中的程序仍然运行于主线程中，当执行一项耗时操作时，不新建一个线程的话很容易导致 Application Not Responding 错误。当需要与 UI线程进行交互时，使用 Handler 机制来进行处理。

```
public abstract class IntentService extends Service {
    private volatile Looper mServiceLooper;
    private volatile ServiceHandler mServiceHandler;
    private String mName;
    private boolean mRedelivery;

    private final class ServiceHandler extends Handler {
        public ServiceHandler(Looper looper) {
            super(looper);
        }

        @Override
        public void handleMessage(Message msg) {
            onHandleIntent((Intent)msg.obj);
            stopSelf(msg.arg1);
        }
    }

    /**
     * Creates an IntentService.  Invoked by your subclass's constructor.
     *
     * @param name Used to name the worker thread, important only for debugging.
     */
    public IntentService(String name) {
        super();
        mName = name;
    }

    /**
     * Sets intent redelivery preferences.  Usually called from the constructor
     * with your preferred semantics.
     *
     * <p>If enabled is true,
     * {@link #onStartCommand(Intent, int, int)} will return
     * {@link Service#START_REDELIVER_INTENT}, so if this process dies before
     * {@link #onHandleIntent(Intent)} returns, the process will be restarted
     * and the intent redelivered.  If multiple Intents have been sent, only
     * the most recent one is guaranteed to be redelivered.
     *
     * <p>If enabled is false (the default),
     * {@link #onStartCommand(Intent, int, int)} will return
     * {@link Service#START_NOT_STICKY}, and if the process dies, the Intent
     * dies along with it.
     */
    public void setIntentRedelivery(boolean enabled) {
        mRedelivery = enabled;
    }

    @Override
    public void onCreate() {
        // TODO: It would be nice to have an option to hold a partial wakelock
        // during processing, and to have a static startService(Context, Intent)
        // method that would launch the service & hand off a wakelock.

        super.onCreate();
        HandlerThread thread = new HandlerThread("IntentService[" + mName + "]");
        thread.start();

        mServiceLooper = thread.getLooper();
        mServiceHandler = new ServiceHandler(mServiceLooper);
    }

    @Override
    public void onStart(@Nullable Intent intent, int startId) {
        Message msg = mServiceHandler.obtainMessage();
        msg.arg1 = startId;
        msg.obj = intent;
        mServiceHandler.sendMessage(msg);
    }

    /**
     * You should not override this method for your IntentService. Instead,
     * override {@link #onHandleIntent}, which the system calls when the IntentService
     * receives a start request.
     * @see android.app.Service#onStartCommand
     */
    @Override
    public int onStartCommand(@Nullable Intent intent, int flags, int startId) {
        onStart(intent, startId);
        return mRedelivery ? START_REDELIVER_INTENT : START_NOT_STICKY;
    }

    @Override
    public void onDestroy() {
        mServiceLooper.quit();
    }

    /**
     * Unless you provide binding for your service, you don't need to implement this
     * method, because the default implementation returns null.
     * @see android.app.Service#onBind
     */
    @Override
    @Nullable
    public IBinder onBind(Intent intent) {
        return null;
    }

    /**
     * This method is invoked on the worker thread with a request to process.
     * Only one Intent is processed at a time, but the processing happens on a
     * worker thread that runs independently from other application logic.
     * So, if this code takes a long time, it will hold up other requests to
     * the same IntentService, but it will not hold up anything else.
     * When all requests have been handled, the IntentService stops itself,
     * so you should not call {@link #stopSelf}.
     *
     * @param intent The value passed to {@link
     *               android.content.Context#startService(Intent)}.
     *               This may be null if the service is being restarted after
     *               its process has gone away; see
     *               {@link android.app.Service#onStartCommand}
     *               for details.
     */
    @WorkerThread
    protected abstract void onHandleIntent(@Nullable Intent intent);
}
```



## Handle 

### Message获取

```
Message message = myHandler.obtainMessage(); 		   //通过 Handler 实例获取
Message message1 = Message.obtain();   			      //通过 Message 获取
Message message2 = new Message();      				 //直接创建新的 Message 实例

通过查看源码可知，Handler 的 obtainMessage() 方法也是调用了 Message 的 obtain() 方法

public final Message obtainMessage()
{
    return Message.obtain(this);
}



public static Message obtain(Handler h) {
        //调用下面的方法获取 Message
        Message m = obtain();
        //将当前 Handler 指定给 message 的 target ，用来区分是哪个 Handler 的消息
        m.target = h;

        return m;
    }
    
//从消息池中拿取 Message，如果有则返回，否则创建新的 Message
public static Message obtain() {
        synchronized (sPoolSync) {
            if (sPool != null) {
                Message m = sPool;
                sPool = m.next;
                m.next = null;
                m.flags = 0; // clear in-use flag
                sPoolSize--;
                return m;
            }
        }
        return new Message();
    }


```

### 发送消息

```
Handler 提供了一些列的方法让我们来发送消息，如 send()系列 post()系列,post方法需要传入一个Runnalbe对象 ,我们来看看post方法源码

    public final boolean post(Runnable r)
    {
       return  sendMessageDelayed(getPostMessage(r), 0);
    }

不过不管我们调用什么方法，最终都会走到 MessageQueue.enqueueMessage(Message,long) 方法。
以 sendEmptyMessage(int) 方法为例：

//Handler
sendEmptyMessage(int)
  -> sendEmptyMessageDelayed(int,int)
    -> sendMessageAtTime(Message,long)
      -> enqueueMessage(MessageQueue,Message,long)
  			-> queue.enqueueMessage(Message, long);
从中可以发现 MessageQueue 这个消息队列，负责消息的入队，出队。
```

主线程向子线程发送消息

```
声明一个Handler类型的私有变量，进行默认初始化为null。

private Handler handler1;

new Thread(new Runnable() {
            @Override
            public void run() {
                Looper.prepare();
                handler1 = new Handler();
                Looper.loop();
                Log.e("child thread", "child thread end");
            }
        }).start();
        
在主线程中向子线程中发送消息

while (handler1 == null) {

        }

        handler1.sendEmptyMessage(0);
        handler1.getLooper().quitSafely();
```

## Provider

读取联系人、获取手机相册、视频等，这些都是系统暴露出来的接口，也就是内容提供器。

## MVVM模式

Model :实体类

View:xml

ViewModel:LiveData和MutableLiveData 实际上基本都是用MutableLiveData 因为他是可变动的

###### 

ViewModel&LiveData:

```
package com.example.mvvm_demo.model;

import androidx.lifecycle.MutableLiveData;
import androidx.lifecycle.ViewModel;

public class MainViewModel extends ViewModel {
    private MutableLiveData<Integer> number;

    public MutableLiveData<Integer> getNumber() {
        if (number == null) {
            number = new MutableLiveData<>();
            number.setValue(0);
        }
        return number;
    }

    public void addNumber(int number) {
        this.number.setValue(getNumber().getValue() + number);
    }
}


```

DataBinding:

```
android {
    ......
    defaultConfig {
        ......
        //下面这个添加上
        dataBinding{
            enabled true
        }
    }
    ......
}
```

```
<?xml version="1.0" encoding="utf-8"?>
<layout xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:app="http://schemas.android.com/apk/res-auto"
    xmlns:tools="http://schemas.android.com/tools">

    <data>
        <variable
            name="viewModel"
            type="com.example.mvvm_demo.model.MainViewModel" />

    </data>

    <androidx.constraintlayout.widget.ConstraintLayout
        android:layout_width="match_parent"
        android:layout_height="match_parent"
        tools:context=".MainActivity">

        <TextView
            android:layout_width="wrap_content"
            android:layout_height="wrap_content"
            android:text="Hello World!"
            app:layout_constraintBottom_toBottomOf="parent"
            app:layout_constraintLeft_toLeftOf="parent"
            app:layout_constraintRight_toRightOf="parent"
            app:layout_constraintTop_toTopOf="parent" />
        <Button
            android:id="@+id/button"
            android:layout_width="wrap_content"
            android:layout_height="wrap_content"
            android:text="button"
            android:onClick="@{v -> viewModel.addNumber(2)}"
            app:layout_constraintBottom_toBottomOf="parent"
            app:layout_constraintLeft_toLeftOf="parent"
            app:layout_constraintRight_toRightOf="parent"
            app:layout_constraintTop_toTopOf="parent"/>

    </androidx.constraintlayout.widget.ConstraintLayout>
</layout>
```



```
package com.example.mvvm_demo;

import androidx.appcompat.app.AppCompatActivity;
import androidx.databinding.DataBindingUtil;
import androidx.lifecycle.Observer;
import androidx.lifecycle.ViewModelProvider;

import android.os.Bundle;

import com.example.mvvm_demo.databinding.ActivityMainBinding;
import com.example.mvvm_demo.model.MainViewModel;

public class MainActivity extends AppCompatActivity {

    private ActivityMainBinding binding;
    private MainViewModel mainViewModel;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        binding = DataBindingUtil.setContentView(this,R.layout.activity_main);
//        setContentView(R.layout.activity_main);
        mainViewModel = new ViewModelProvider(this,ViewModelProvider.AndroidViewModelFactory.getInstance(getApplication())).get(MainViewModel.class);
        binding.setViewModel(mainViewModel); //给layout设置data标签的值
        binding.setLifecycleOwner(this);
//        mainViewModel.getNumber().observe(this, new Observer<Integer>() {
//            @Override
//            public void onChanged(Integer integer) {
//            }
//        });
    }
}

```



## 复制粘贴

```

ClipboardManager clipboard = (ClipboardManager)getSystemService(Context.CLIPBOARD_SERVICE);

对于 Text：
// Creates a new text clip to put on the clipboard
ClipData clip = ClipData.newPlainText("simple text", "Hello, World!");


对于URI：
以下代码段通过将记录 ID 编码到提供程序的内容 URI 来构建 URI。在 URI 中对标识符进行编码部分对此方法进行了更详细的说明
// Creates a Uri based on a base Uri and a record ID based on the contact's last name
// Declares the base URI string
private static final String CONTACTS = "content://com.example.contacts";

// Declares a path string for URIs that you use to copy data
private static final String COPY_PATH = "/copy";

// Declares the Uri to paste to the clipboard
Uri copyUri = Uri.parse(CONTACTS + COPY_PATH + "/" + lastName);
...

// Creates a new URI clip object. The system uses the anonymous getContentResolver() object to
// get MIME types from provider. The clip object's label is "URI", and its data is
// the Uri previously created.
ClipData clip = ClipData.newUri(getContentResolver(), "URI", copyUri);


对于 Intent：
以下代码段为应用构建一个 Intent，然后将其放入剪贴对象中：
// Creates the Intent
Intent appIntent = new Intent(this, com.example.demo.myapplication.class);

...

// Creates a clip object with the Intent in it. Its label is "Intent" and its data is
// the Intent object created previously
ClipData clip = ClipData.newIntent("Intent", appIntent);

```



## 屏幕常亮

```
 getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
```



## 截屏

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        //禁止当前页面截屏
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        setContentView(R.layout.activity_main);
    }
    
    可以截屏 window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE);
    
    测试结果：执行onReStart()后生效。

## 弹窗

### DialogFragment代替AlertDialog实现弹出对话框

1、为什么要有DialogFragment？

DialogFragment是在3.0版本引入的，既然已经存在了AlertDialog，为什么还要引入DialogFragment呢？它存在的意义是什么？

因为DialogFragment和Fragment基本一致的生命周期，当屏幕旋转导致Activity的生命周期会重新调用，此时AlertDialog会消失，如果处理不当很可能引发异常，而DialogFragment对话框会随之自动调整对话框方向，DialogFragment的出现完美的解决了横竖屏幕切换Dialog消失的问题，同时也有恢复数据的功能

继承DialogFragment，并实现onCreateDialog方法。（推荐此方式）

    @NonNull
    @Override
    public Dialog onCreateDialog(Bundle savedInstanceState) {
        AlertDialog.Builder builder = new AlertDialog.Builder(getActivity());
        builder.setMessage("您确定要退出吗?").setPositiveButton("OK", new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) {
                dismiss();
            }
        }).setNegativeButton("Cancel", null);
        return builder.create();
    }
在Activity中使用：

```
FragmentTransaction mFragTransaction = getFragmentManager().beginTransaction();  
Fragment fragment =  getFragmentManager().findFragmentByTag("dialogFragment");  
if(fragment!=null){   
    mFragTransaction.remove(fragment);  
}  
AlertDialogFragment dialogFragment = new AlertDialogFragment();
dialogFragment.show(mFragTransaction, "dialogFragment");
```



## 路径相关

### 获取U盘路径

```
StorageManager storageManager = (StorageManager) getSystemService(Context.STORAGE_SERVICE);
        if (null != storageManager) {
            List<StorageVolume> volumeInfoList = storageManager.getStorageVolumes();
            for (StorageVolume storageVolume : volumeInfoList) {
                if (Build.VERSION.SDK_INT >= 30) {
                    Log.d(TAG, "onCreate: " + storageVolume.getDescription(this)
                            + ", name = " + storageVolume.getMediaStoreVolumeName()
                            + ", path = " + storageVolume.getDirectory().getPath());
                }
            }
        }
```
