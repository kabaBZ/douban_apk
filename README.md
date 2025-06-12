### 环境搭建
uv sync
uv tool install --with frida frida-tools
### windows环境 
node
scrcpy
zerotier(远程调试)
adb
### 远程调试命令
手机usb连电脑adb  
电脑执行 adb tcpip 5555  设置手机监听5555

后续操作就可以脱离usb了
adb connect ip
adb shell
su
/data/local/tmp/frida-server -l 0.0.0.0:6666
frida -H 192.168.192.66:6666 -f <appName> -l <hookJsFilePath>
