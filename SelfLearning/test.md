# **OkHttp框架解析及使用**

 

### 1. **OkHttp介绍**

OkHttp是square公司贡献的一个处理网络请求的开源框架，是目前Android开发使用最广泛的一个网络框架，从Android4.4开始，httpURLconnection的底层实现采用的就是OkHttp。OkHttp内部实现就是利用java基础，对socket进行封装，实现http通信。最重要的两个关键点就是分发器和5个拦截器。

\1) 支持HTTP2.0；

\2) 同时支持同步与异步请求；

\3) 同时具备HTTP与WebSocket功能；

\4) 拥有自动维护的socket连接池，复用TCP连接；

\5) 拥有队列线程池；

\6) 拥有Interceptors(拦截器)，自行处理请求与响应额外需求(例：请求失败重试、响应内容重定向、自动对连接头进行补全等等)

 

### 2. **OkHttp框架解析**

本章源码分析基于 "com.squareup.okhttp3:okhttp:3.14.9"版本

 

\1) 请求整体流程图:


![img](file:///C:\Users\XIAOZH~1\AppData\Local\Temp\ksohtml10304\wps1.jpg)

 

 

 

 

\2) 部分源码分析:

 

RetryAndFollowUpInterceptor（重试和重定向拦截器）:顾名思义，就是对返回的结果进行一系列判断后再次发送请求。

 

@Override

public Response intercept(Chain chain) throws IOException {

  Request request = chain.request();

  RealInterceptorChain realChain = (RealInterceptorChain) chain;

  Transmitter transmitter = realChain.transmitter();

 

  int followUpCount = 0;

  Response priorResponse = null;

  while (true) {

   // 准备连接请求

   transmitter.prepareToConnect(request);

   ...

   Response response;

   boolean success = false;

 

   // 执行下面的拦截器的功能，获取Response；

 try {
 	response = realChain.proceed(request, transmitter, null);
  success = true;
	} catch (RouteException e) {

//路由异常，请求还没还发出，尝试恢复
  // The attempt to connect via a route failed. The request will not have been sent.
  if (!recover(e.getLastConnectException(), transmitter, false, request)) {
   throw e.getFirstConnectException();
 }
 	continue;
	} catch (IOException e) {

// IO异常，请求可能已经发出。尝试恢复

 // An attempt to communicate with a server failed. The request may have been sent.
	 boolean requestSendStarted = !(e instanceof ConnectionShutdownException);
	 if (!recover(e, transmitter, requestSendStarted, request)) throw e;
	 continue;
	} finally {
	 // The network call threw an exception. Release any resources.
	 if (!success) {
	  transmitter.exchangeDoneDueToException();
	 }
	}

   // 根据Response的返回码来判断要执行重试还是重定向；

   Request followUp = followUpRequest(response, route);

   ...

   if (followUp == null) {

​    // 如果followUpRequest返回的Request为空，那边就表示不需要执行重试或者重定向，直接返回数据；

​    return response;

   }

 

   RequestBody followUpBody = followUp.body();

   if (followUpBody != null && followUpBody.isOneShot()) {

​    // 如果followUpBody 请求体不为空，并且不需要重试，那么就返回response；

​    return response;

   }

 

   // 判断重试或者重定向的次数是否超过最大的次数，默认是20次， 是的话则抛出异常；

   if (++followUpCount > MAX_FOLLOW_UPS) {

​    throw new ProtocolException("Too many follow-up requests: " + followUpCount);

   }

   // 将需要重试或者重定向的请求赋值给新的请求；

   request = followUp;

  }

 }

 

 

BridgeInterceptor(桥接拦截器):请求发出之前补全请求头；响应收到之后解析cookie，并保存本地（cookieJar需要调用方自己实现存储和获取）,如果是使用gzip返回的数据，则使用 GzipSource 包装便于解析。

@Override 

public Response intercept(Chain chain) throws IOException {

  Request userRequest = chain.request();

  Request.Builder requestBuilder = userRequest.newBuilder();

  

  //下面一大段代码都是处理Header相关信息的

  RequestBody body = userRequest.body();

  if (body != null) {

   MediaType contentType = body.contentType();

   if (contentType != null) {

​    requestBuilder.header("Content-Type", contentType.toString());

   }

 

   long contentLength = body.contentLength();

   if (contentLength != -1) {

​    requestBuilder.header("Content-Length", Long.toString(contentLength));

​    requestBuilder.removeHeader("Transfer-Encoding");

   } else {

​    requestBuilder.header("Transfer-Encoding", "chunked");

​    requestBuilder.removeHeader("Content-Length");

   }

  }

 

  if (userRequest.header("Host") == null) {

   requestBuilder.header("Host", hostHeader(userRequest.url(), false));

  }

//建立长连接

  if (userRequest.header("Connection") == null) {

   requestBuilder.header("Connection", "Keep-Alive");

  }

 

  //如果我们不自定义编解码方式，这里添加了Gzip的编解码

  boolean transparentGzip = false;

  if (userRequest.header("Accept-Encoding") == null && userRequest.header("Range") == null) {

   transparentGzip = true;

   requestBuilder.header("Accept-Encoding", "gzip");

  }

 

  //在创建ohHttpClient的时候，添加的cookiejar, 这里会对其进行写入。

  List<Cookie> cookies = cookieJar.loadForRequest(userRequest.url());

  if (!cookies.isEmpty()) {

   requestBuilder.header("Cookie", cookieHeader(cookies));

  }

 

  if (userRequest.header("User-Agent") == null) {

   requestBuilder.header("User-Agent", Version.userAgent());

  }

  

  //以上是请求前的，前期头的处理

  //通过chain，调用下一个拦截器，并得到结果

  Response networkResponse = chain.proceed(requestBuilder.build());

//收到结果之后，是否保存cookie

  HttpHeaders.receiveHeaders(cookieJar, userRequest.url(), networkResponse.headers());

 

  Response.Builder responseBuilder = networkResponse.newBuilder()

​    .request(userRequest);

//如果我们没有自定义编解码方式，这里会创建 能自动解压的responseBody--GzipSource

  if (transparentGzip

​    && "gzip".equalsIgnoreCase(networkResponse.header("Content-Encoding"))

​    && HttpHeaders.hasBody(networkResponse)) {

   GzipSource responseBody = new GzipSource(networkResponse.body().source());

   Headers strippedHeaders = networkResponse.headers().newBuilder()

​     .removeAll("Content-Encoding")

​     .removeAll("Content-Length")

​     .build();

   responseBuilder.headers(strippedHeaders);

   responseBuilder.body(new RealResponseBody(strippedHeaders, Okio.buffer(responseBody)));

  }

 

  return responseBuilder.build();

 }

 

CacheInterceptor(缓存拦截器):根据策略和一系列判断直接返回缓存起来的结果，使请求更快速高效，获得结果后判断是否缓存结果。

 

 @Override 

public Response intercept(Chain chain) throws IOException {

  //获取当前请求的缓存响应

  Response cacheCandidate = cache != null

​    ? cache.get(chain.request())

​    : null;

 

  long now = System.currentTimeMillis();

​	

  /**

  \* 这里面会根据请求头中的缓存配置是否使用缓存（比方是否有If-None-Match、If-Modified-Since、maxAge），

  \* 来赋值strategy的响应cacheResponse是否为空，为空则不使用缓存

  */

  CacheStrategy strategy = new CacheStrategy.Factory(now, chain.request(), cacheCandidate).get();

  Request networkRequest = strategy.networkRequest;

  Response cacheResponse = strategy.cacheResponse;

 

  //统计缓存使用次数

  if (cache != null) {

​    cache.trackResponse(strategy);

  }

 

  //如果缓存响应为空，则直接关闭缓存对象

  if (cacheCandidate != null && cacheResponse == null) {

​    closeQuietly(cacheCandidate.body()); 

  }

 

  //当CacheStrategy里的onlyIfCached这个值配置为false时，networkRequest会为空，这个值表示不使用网络

  //不使用网络，并且缓存响应也为空时，就报错504

  if (networkRequest == null && cacheResponse == null) {

​    return new Response.Builder()

​      .request(chain.request())

​      .protocol(Protocol.HTTP_1_1)

​      .code(504)

​      .message("Unsatisfiable Request (only-if-cached)")

​      .body(Util.EMPTY_RESPONSE)

​      .sentRequestAtMillis(-1L)

​      .receivedResponseAtMillis(System.currentTimeMillis())

​      .build();

  }

 

  //不使用网络，但是有缓存响应，则返回缓存响应

  if (networkRequest == null) {

​    return cacheResponse.newBuilder()

​      .cacheResponse(stripBody(cacheResponse))

​      .build();

  }

 

  Response networkResponse = null;

  try {

​    //向下调用拦截器，请求网络

​    networkResponse = chain.proceed(networkRequest);

  } finally {

​    // If we're crashing on I/O or otherwise, don't leak the cache body.

​    if (networkResponse == null && cacheCandidate != null) {

​      closeQuietly(cacheCandidate.body());

​    }

  }

 

  // If we have a cache response too, then we're doing a conditional get.

  if (cacheResponse != null) {

​    if (networkResponse.code() == HTTP_NOT_MODIFIED) {

​      //当缓存不为空，且服务器返回304时，则说明缓存内容没有变，使用缓存响应

​      Response response = cacheResponse.newBuilder()

​        .headers(combine(cacheResponse.headers(), networkResponse.headers()))

​        .sentRequestAtMillis(networkResponse.sentRequestAtMillis())

​        .receivedResponseAtMillis(networkResponse.receivedResponseAtMillis())

​        .cacheResponse(stripBody(cacheResponse))

​        .networkResponse(stripBody(networkResponse))

​        .build();

​      networkResponse.body().close();

 

​      // Update the cache after combining headers but before stripping the

​      // Content-Encoding header (as performed by initContentStream()).

​      cache.trackConditionalCacheHit();

​      //更新缓存

​      cache.update(cacheResponse, response);

​      //返回缓存响应

​      return response;

​    } else {

​      //服务器返回非304，则缓存不可用，关闭缓存

​      closeQuietly(cacheResponse.body());

​    }

  }

 

  Response response = networkResponse.newBuilder()

​    .cacheResponse(stripBody(cacheResponse))

​    .networkResponse(stripBody(networkResponse))

​    .build();

 

  if (cache != null) {

​    //如果规则配置使用缓存，则更新最新的响应到缓存里

​    if (HttpHeaders.hasBody(response) && CacheStrategy.isCacheable(response, networkRequest)) {

​      CacheRequest cacheRequest = cache.put(response);

​      //返回通过网络最新响应重新构造出来的响应给上层

​      return cacheWritingResponse(cacheRequest, response);

​    }

​		//规则配置了不使用缓存，则删除缓存

​    if (HttpMethod.invalidatesCache(networkRequest.method())) {

​      try {

​        cache.remove(networkRequest);

​      } catch (IOException ignored) {

​        // The cache cannot be written.

​      }

​    }

  }

 

  return response;

}

 

ConnectInterceptor(连接拦截器): 	

 @Override public Response intercept(Chain chain) throws IOException {

  RealInterceptorChain realChain = (RealInterceptorChain) chain;

  Request request = realChain.request();

  Transmitter transmitter = realChain.transmitter();

 

  // We need the network to satisfy this request. Possibly for validating a conditional GET.

  boolean doExtensiveHealthChecks = !request.method().equals("GET");

  Exchange exchange = transmitter.newExchange(chain, doExtensiveHealthChecks);

 

  return realChain.proceed(request, transmitter, exchange);

 }

### 3. **OkHttp的简单使用**

 

\1) 创建Client和Request:

​    Get请求:

OkHttpClient client = new OkHttpClient.Builder().build();

​    Request request = new Request.Builder().

​        url("https://www.baidu.com").

​        build();

​    Call call = client.newCall(request);

Post请求：

OkHttpClient client = new OkHttpClient();

RequestBody body = RequestBody.create(JSON, json);

Request request = new Request.Builder()

​               .url(url)

​               .post(body)

​               .build();

 	Call call = client.newCall(request);

 

\2) 同步请求:
  Response response = client.newCall(request).execute();

\3) 异步请求:

  client.newCall(request).enqueue(new Callback() {

   @Override

   public void onFailure(@NotNull Call call, @NotNull IOException e) {

​		 //todo handle request failed

   }

   @Override

   public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {

​     //todo handle Response

   }

});

### 4. **后续自主学习扩展**

OkHttp的高级封装版本Retrofit,其适配了Gson、RxJava等强大工具，能使用户更专注逻辑层面而不是代码层面。