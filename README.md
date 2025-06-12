### 环境搭建
```shell
uv sync
uv tool install --with frida frida-tools
```

### windows环境 
node
scrcpy
zerotier(远程调试)
adb
### 远程调试命令
手机usb连电脑adb  
电脑执行,设置手机监听5555 
```
adb tcpip 5555
```

后续操作就可以脱离usb了
```shell
adb connect ip
adb shell
su
/data/local/tmp/frida-server -l 0.0.0.0:6666
frida -H 192.168.192.66:6666 -f <appName> -l <hookJsFilePath>
```

### by_pass_frida_check
```shell
frida -U -f com.douban.frodo -l D:\workSpace\ReverseEngineer\douban_apk\bypass_frida_check.js
```


### java_layer_hook
```shell
frida -U -F com.douban.frodo -l D:\workSpace\ReverseEngineer\douban_apk\hook_java_layer.js

frida -U -F com.douban.frodo -l D:\workSpace\ReverseEngineer\douban_apk\hook_java_layer.js > java_hook.log // 日志写文件
```

