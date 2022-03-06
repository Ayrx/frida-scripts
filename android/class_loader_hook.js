/**
Re-implementation of hooking Android's class loader described by
Marcus Mengs (@mame82):
https://twitter.com/mame82/status/1362667014779768832/photo/1
**/
const handled_classes = new Set();
const callback_map = new Map();

function on_new_class_load(name) {
    let s = callback_map.get(name);
    if (s !== undefined) {
        for (let callback of s) {
            callback();
        }
    }
}

function hook_load_class() {
    const re_ClassLinkerFindClass = /art[0-9]{1,2}ClassLinker[0-9]{1,2}FindClassE/;
    const lib_art = Module.load("libart.so");

    const e = lib_art
        .enumerateExports()
        .filter((ed) => ed.name.match(re_ClassLinkerFindClass))

    if (e.length <= 0) {
        console.log("ERROR: Cannot hook ClassLinker::findClass");
        return;
    }

    Interceptor.attach(e[0].address, {
        onEnter(args) {
            this.name = args[2].readUtf8String();
        },
        onLeave(res) {
            if (handled_classes.has(this.name)) return;

            if (res.toInt32() !== 0) {
                handled_classes.add(this.name);

                let tmp = (this.name).match(/^L(.*);$/);
                if (tmp !== null && tmp.length > 1) {
                    const readable_name = tmp[1].replace(/\//g, ".");
                    on_new_class_load(readable_name);
                }
            }
        }
    });
}

function java_use_once_loaded(class_name, callback) {
    try {
        callback(Java.use(class_name));
        return;
    } catch (e) {
        if (callback_map.has(class_name)) {
            let s = callback_map.get(class_name);
            if (s !== undefined) {
                s.add(callback);
            }
        } else {
            let s = new Set();
            s.add(callback);
            callback_map.set(class_name, s);
        }
    }
}

Java.perform(hook_load_class)
