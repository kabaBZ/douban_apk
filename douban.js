
// function hook_JNI_OnLoad(){
//     let module = Process.findModuleByName("libmsaoaidsec.so")
//     Interceptor.attach(module.base.add(0x13A4C), {
//         onEnter(args){
//             console.log("JNI_OnLoad")
//         }
//     })
// }

function hook_dlopen() {
    Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"), {
        onEnter: function (args) {
            this.fileName = args[0].readCString();
            console.log(`\n[+] dlopen onEnter ==> ${this.fileName}`);
            if (this.fileName && this.fileName.includes("libmsaoaidsec.so")) {
                hook_linker_call_constructors();
            }
        }, onLeave: function (retval) {
            if (this.fileName != null && this.fileName.indexOf("libmsaoaidsec.so") >= 0) {
                let JNI_OnLoad = Module.getExportByName(this.fileName, 'JNI_OnLoad')
                console.log(`dlopen onLeave JNI_OnLoad: ${JNI_OnLoad}`)
            }
            console.log(`[-] dlopen onLeave ==> ${this.fileName}`);
        }
    });
}

function hook_linker_call_constructors() {
    let call_constructors = Module.getBaseAddress('linker64').add(0x2FAC4)  // __dl__ZN6soinfo17call_constructorsEv
    let listener = Interceptor.attach(call_constructors, {
        onEnter: function (args) {
            console.log('[++++] call_constructors onEnter')
            // console.log("libmsaoaidsec.so --- " + Process.findModuleByName("libmsaoaidsec.so").base)
            let secmodule = Process.findModuleByName("libmsaoaidsec.so")
            if (secmodule != null) {
                // debug阶段
                // hook_pthred_create()
                // 实践阶段
                make_function_null("libmsaoaidsec.so", 0x1CEF8)  // 1c544的上层调用
                make_function_null("libmsaoaidsec.so", 0x1B924)  // 1b8d4的上层调用
                make_function_null("libmsaoaidsec.so", 0x2701C)  // 26e5c的上层调用
                listener.detach()  // 移除hook 防止多次替换，debug阶段不需要detach
            }
        }, onLeave: function (retval) {
            console.log("[-] call_constructors onLeave");
        }
    })
}

function anti_frida_check() {
    // 3. 绕过/proc/maps检测
    Interceptor.attach(Module.findExportByName('libc.so', 'fopen'), {
        onEnter(args) {
            this.fileName = Memory.readCString(args[0]);
            const fileName = Memory.readCString(args[0]);
            console.log(`fopen: ${fileName}`)
            if (fileName && fileName.includes("/proc/self/maps")) {
                console.log("[!] Redirecting /proc/self/maps to /dev/null");
                args[0] = Memory.allocUtf8String("/dev/null");
            }
        },
        // onLeave(retval) {
        //     // if (this.fileName && this.fileName.includes("/cmdline")) {
        //     //     console.log(`[!] cmdlineData=====> ${retval}`);
        //     //     // const newCmdline = "com.example.app";
        //     //     // const fd = ptr(args[0]).add(0x10); // 假设偏移量，需动态计算
        //     //     // ptr(fd).writeUtf8String(newCmdline);
        //     // }
        // }
    });
}

function hook_pthred_create() {
    let pthread_create = Module.findExportByName("libc.so", "pthread_create");
    Interceptor.attach(pthread_create, {
        onEnter: function (args) {
            let func_addr = args[2];
            let secmodule = Process.findModuleByName("libmsaoaidsec.so")
            var offset = func_addr.sub(secmodule.base)
            console.log(`[!] found pthread_create, execute function is at ${func_addr}, offest: ${offset}`);
            // if (secmodule != null) {
            // }
        }
    })
}

// 定义一个函数anti_maps，用于阻止特定字符串的搜索匹配，避免检测到敏感内容如"Frida"或"REJECT"
function anti_maps() {
    // 查找libc.so库中strstr函数的地址，strstr用于查找字符串中首次出现指定字符序列的位置
    var pt_strstr = Module.findExportByName("libc.so", 'strstr');
    // 查找libc.so库中strcmp函数的地址，strcmp用于比较两个字符串
    var pt_strcmp = Module.findExportByName("libc.so", 'strcmp');
    // 使用Interceptor模块附加到strstr函数上，拦截并修改其行为
    Interceptor.attach(pt_strstr, {
        // 在strstr函数调用前执行的回调
        onEnter: function (args) {
            // 读取strstr的第一个参数（源字符串）和第二个参数（要查找的子字符串）
            var str1 = args[0].readCString();
            var str2 = args[1].readCString();
            // 检查子字符串是否包含"REJECT"或"frida"，如果包含则设置hook标志为true
            if (str2.indexOf("REJECT") !== -1  || str2.indexOf("frida") !== -1) {
                this.hook = true;
            }
        },
        // 在strstr函数调用后执行的回调
        onLeave: function (retval) {
            // 如果之前设置了hook标志，则将strstr的结果替换为0（表示未找到），从而隐藏敏感信息
            if (this.hook) {
                console.log('frida maps strstr anti !!!')
                retval.replace(0);
            }
        }
    });

    // 对strcmp函数做类似的处理，防止通过字符串比较检测敏感信息
    Interceptor.attach(pt_strcmp, {
        onEnter: function (args) {
            var str1 = args[0].readCString();
            var str2 = args[1].readCString();
            if (str2.indexOf("REJECT") !== -1  || str2.indexOf("frida") !== -1) {
                this.hook = true;
            }
        },
        onLeave: function (retval) {
            if (this.hook) {
                console.log('frida maps strcmp anti !!!')
                // strcmp返回值为0表示两个字符串相等，这里同样替换为0以避免匹配成功
                retval.replace(0);
            }
        }
    });
}

function make_function_null(module_name, offset) {
    let secmodule = Process.findModuleByName(module_name)
    if (secmodule != null) {
        console.log(`找到${module_name}模块`)
        Interceptor.replace(
            secmodule.base.add(offset), 
            new NativeCallback(function () {
                console.log(`${module_name} ==> ${offset} 函数置空替换成功`)
            }, "void", [])
        );
    };
}


console.log("start hook dlopen")
hook_dlopen()
// anti_frida_check()
// hook_pthred_create()
// anti_maps()