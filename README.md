# ngx-http-arg-from-response-module
将nginx的响应变为nginx的参数


## Directives
```
Syntax:	 arg-from-resp on | off;
Default: redis-visit off;
Context: http
```
是否开启该模块



```
Syntax:	 arg-name-uri argname uri;
Default: -;
Context: server
```

从`location uri` 中获取响应，作为nginx参数 `$argname`. 可以配置多个


```nginx
arg-name-uri  arg1 /_redis;
arg-name-uri  arg2 /_inc;
arg-name-uri  arg3 /_inc;
```

