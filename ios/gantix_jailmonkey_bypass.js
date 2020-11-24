/**
Root detection bypass script for Gantix JailMoney
https://github.com/GantMan/jail-monkey
**/
const klass = ObjC.classes.JailMonkey;
Interceptor.attach(klass['- isJailBroken'].implementation, {
    onLeave: function (retval) {
        retval.replace(0);
    }
});
