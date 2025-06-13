// function hook1() {
//     let d = Java.use("i0.d");
//     d["E"].implementation = function (str, str2, str3) {
//         console.log('E is called' + ', ' + 'str: ' + str + ', ' + 'str2: ' + str2 + ', ' + 'str3: ' + str3);
//         let ret = this.E(str, str2, str3);
//         console.log('E ret value is ' + ret);
//         return ret;
//     };
// }
//
//
// // function main() {
// //     Java.perform(function () {
// //         hook1()
// //     })
// // }
//
// function hook_pth() {
//     var pth_create = Module.findExportByName("libc.so", "pthread_create");
//     console.log("[pth_create]", pth_create);
//     Interceptor.attach(pth_create, {
//         onEnter: function (args) {
//             var module = Process.findModuleByAddress(args[2]);
//             if (module != null) {
//                 console.log("开启线程-->", module.name, args[2].sub(module.base));
//                 if (module.name.indexOf("libmsaoaidsec.so") != -1) {
//                     // nopFunc(0x1b8d4)
//                     // nopFunc(0x1B924)
//                     Interceptor.replace(module.base.add(0x1B924), new NativeCallback(function () {
//                         console.log("替换成功")
//                     }, "void", ["void"]))
//
//                     // nopFunc(0x1B924)
//
//                 }
//
//             }
//
//         },
//         onLeave: function (retval) {
//         }
//     });
// }
// hook_pth();
// var dlopen = Module.findExportByName(null, "dlopen");
// var android_dlopen_ext = Module.findExportByName(null, "android_dlopen_ext");
// Interceptor.attach(dlopen, {
//     onEnter: function (args) {
//         var path_ptr = args[0];
//         var path = ptr(path_ptr).readCString();
//         console.log("[dlopen -> enter", path);
//     },
//     onLeave: function (retval) {
//         console.log("dlopen -> leave")
//
//     }
// });
// Interceptor.attach(android_dlopen_ext, {
//     onEnter: function (args) {
//         var path_ptr = args[0];
//         var path = ptr(path_ptr).readCString();
//         console.log("[android_dlopen_ext -> enter", path);
//         if (args[0].readCString() != null && args[0].readCString().indexOf("libmsaoaidsec.so") >= 0) {
//             hook_call_constructors()
//         }
//     },
//     onLeave: function (retval) {
//         console.log("android_dlopen_ext -> leave")
//
//     }
// });
//
//
//

//
//
// // setImmediate(main)



function hook_call_constructors() {
    var linker64_base_addr = Module.getBaseAddress("linker64");
    var call_constructors_func_off = 0x2FAC4;
    var call_constructors_func_addr = linker64_base_addr.add(call_constructors_func_off);
    var listener = Interceptor.attach(call_constructors_func_addr, {
        onEnter: function (args) {
            hook_pthred_create()
            // console.log("call_constructors -> enter")
            // var module = Process.findModuleByName("libmsaoaidsec.so")
            // if (module != null) {
            //     Interceptor.replace(module.base.add(0x1B924), new NativeCallback(function () {
            //         console.log("替换成功")
            //     }, "void", []))
            //     listener.detach()
            // }
        },
    })
}

function hook_dlopen() {
    var dlopen = Module.findExportByName(null, "dlopen");
    var android_dlopen_ext = Module.findExportByName(null, "android_dlopen_ext");
    Interceptor.attach(dlopen, {
        onEnter: function (args) {
            var path_ptr = args[0];
            var path = ptr(path_ptr).readCString();
            console.log("[dlopen -> enter", path);
        },
        onLeave: function (retval) {
            console.log("dlopen -> leave")
        }
    });
    Interceptor.attach(android_dlopen_ext, {
        onEnter: function (args) {
            var path_ptr = args[0];
            var path = ptr(path_ptr).readCString();
            console.log("[android_dlopen_ext -> enter", path);
            if (path.indexOf("libmsaoaidsec.so")>= 0) {
                hook_call_constructors()
            }
        },
        onLeave: function (retval) {
            console.log("android_dlopen_ext -> leave")
        }
    });
}
function hook_pthred_create() {
    var pth_create = Module.findExportByName(null, "pthread_create");
    console.log("[pth_create]", pth_create);
    Interceptor.attach(pth_create, {
        onEnter: function (args) {
            var module = Process.findModuleByAddress(args[2]);
            if (module != null) {
                console.log("开启线程-->", module.name, args[2].sub(module.base));
            }

        },
        onLeave: function (retval) {}
    });
}

hook_dlopen();

