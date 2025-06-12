function hook() {
    Java.perform(function (){
        let d = Java.use("i0.d");
        d["H"].implementation = function (str, str2, str3) {
            console.log(`d.H is called: str=${str}, str2=${str2}, str3=${str3}`);
            let result = this["H"](str, str2, str3);
            console.log(`d.H result=${result}`);
            return result;
        };
    })
}

hook()
