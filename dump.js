// 降维打击版 dump.js - V7 最终完美版 (修复内存越界致命 Bug)

var O_RDONLY = 0;
var O_WRONLY = 1;
var O_RDWR = 2;
var O_CREAT = 512;

var SEEK_SET = 0;
var SEEK_CUR = 1;
var SEEK_END = 2;

function allocStr(str) { return Memory.allocUtf8String(str); }
function putStr(addr, str) { if (typeof addr == "number") addr = ptr(addr); return addr.writeUtf8String(str); }
function getByteArr(addr, l) { if (typeof addr == "number") addr = ptr(addr); return addr.readByteArray(l); }
function getU8(addr) { if (typeof addr == "number") addr = ptr(addr); return addr.readU8(); }
function putU8(addr, n) { if (typeof addr == "number") addr = ptr(addr); return addr.writeU8(n); }
function getU16(addr) { if (typeof addr == "number") addr = ptr(addr); return addr.readU16(); }
function putU16(addr, n) { if (typeof addr == "number") addr = ptr(addr); return addr.writeU16(n); }
function getU32(addr) { if (typeof addr == "number") addr = ptr(addr); return addr.readU32(); }
function putU32(addr, n) { if (typeof addr == "number") addr = ptr(addr); return addr.writeU32(n); }
function getU64(addr) { if (typeof addr == "number") addr = ptr(addr); return addr.readU64(); }
function putU64(addr, n) { if (typeof addr == "number") addr = ptr(addr); return addr.writeU64(n); }
function getPt(addr) { if (typeof addr == "number") addr = ptr(addr); return addr.readPointer(); }
function putPt(addr, n) { if (typeof addr == "number") addr = ptr(addr); if (typeof n == "number") n = ptr(n); return addr.writePointer(n); }
function malloc(size) { return Memory.alloc(size); }

function safeFindExport(name) {
    if (typeof ApiResolver !== 'undefined') {
        try {
            var resolver = new ApiResolver("module");
            var matches = resolver.enumerateMatches("exports:*!" + name);
            if (matches.length > 0) return matches[0].address;
        } catch(e) {}
    }
    
    var mods = Process.enumerateModules();
    for (var i = 0; i < mods.length; i++) {
        var exports = mods[i].enumerateExports();
        for (var j = 0; j < exports.length; j++) {
            if (exports[j].name === name) {
                return exports[j].address;
            }
        }
    }
    
    if (typeof Module !== 'undefined' && typeof Module.findExportByName === 'function') {
        return Module.findExportByName(null, name);
    }
    return null;
}

function getExportFunction(type, name, ret, args) {
    var nptr = safeFindExport(name);
    if (!nptr) {
        throw new Error("彻底找不到底层 C 函数: " + name);
    }
    
    if (type === "f") {
        return new NativeFunction(nptr, ret, args);
    } else if (type === "d") {
        return nptr.readPointer();
    }
}

var sys_open = null;
var sys_read = null;
var sys_write = null;
var sys_lseek = null;
var sys_close = null;
var sys_remove = null;
var sys_access = null;

function initCoreFunctions() {
    if (sys_open !== null) return;
    sys_open = getExportFunction("f", "open", "int", ["pointer", "int", "int"]);
    sys_read = getExportFunction("f", "read", "int", ["int", "pointer", "int"]);
    sys_write = getExportFunction("f", "write", "int", ["int", "pointer", "int"]);
    sys_lseek = getExportFunction("f", "lseek", "int64", ["int", "int64", "int"]);
    sys_close = getExportFunction("f", "close", "int", ["int"]);
    sys_remove = getExportFunction("f", "remove", "int", ["pointer"]);
    sys_access = getExportFunction("f", "access", "int", ["pointer", "int"]);
}

function getDocumentDir() { return "/tmp"; }

function c_open(pathname, flags, mode) {
    if (typeof pathname == "string") pathname = allocStr(pathname);
    return sys_open(pathname, flags, mode);
}

var modules = null;
function getAllAppModules() {
    modules = new Array();
    var tmpmods = Process.enumerateModules();
    for (var i = 0; i < tmpmods.length; i++) {
        if (tmpmods[i].path && tmpmods[i].path.indexOf(".app") != -1) {
            modules.push(tmpmods[i]);
        }
    }
    return modules;
}

var FAT_MAGIC = 0xcafebabe, FAT_CIGAM = 0xbebafeca;
var MH_MAGIC = 0xfeedface, MH_CIGAM = 0xcefaedfe;
var MH_MAGIC_64 = 0xfeedfacf, MH_CIGAM_64 = 0xcffaedfe;
var LC_SEGMENT = 0x1, LC_SEGMENT_64 = 0x19;
var LC_ENCRYPTION_INFO = 0x21, LC_ENCRYPTION_INFO_64 = 0x2C;

function pad(str, n) { return Array(n-str.length+1).join("0")+str; }
function swap32(value) {
    value = pad(value.toString(16),8)
    var result = "";
    for(var i = 0; i < value.length; i=i+2){
        result += value.charAt(value.length - i - 2);
        result += value.charAt(value.length - i - 1);
    }
    return parseInt(result,16)
}

function dumpModule(name) {
    if (modules == null) modules = getAllAppModules();
    var targetmod = null;
    for (var i = 0; i < modules.length; i++) {
        if (modules[i].path && modules[i].path.indexOf(name) != -1) {
            targetmod = modules[i]; break;
        }
    }
    if (targetmod == null) return;
    
    var modbase = targetmod.base;
    var newmodpath = getDocumentDir() + "/" + targetmod.name + ".fid";
    var oldmodpath = targetmod.path;

    if(!sys_access(allocStr(newmodpath),0)) sys_remove(allocStr(newmodpath));

    var fmodule = c_open(newmodpath, O_CREAT | O_RDWR, 0);
    var foldmodule = c_open(oldmodpath, O_RDONLY, 0);

    if (fmodule == -1 || foldmodule == -1) return;

    var size_of_mach_header = 0;
    var magic = getU32(modbase);
    var cur_cpu_type = getU32(modbase.add(4));
    var cur_cpu_subtype = getU32(modbase.add(8));
    
    if (magic == MH_MAGIC || magic == MH_CIGAM) { size_of_mach_header = 28; } 
    else if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64) { size_of_mach_header = 32; }

    var BUFSIZE = 4096;
    var buffer = malloc(BUFSIZE);
    sys_read(foldmodule, buffer, BUFSIZE);

    var fileoffset = 0;
    var filesize = 0;
    magic = getU32(buffer);
    
    // 核心修复：修改隐式逻辑 Bug
    if (magic == FAT_CIGAM || magic == FAT_MAGIC) {
        var off = 4;
        var archs = swap32(getU32(buffer.add(off)));
        for (var i = 0; i < archs; i++) {
            var cputype = swap32(getU32(buffer.add(off + 4)));
            var cpusubtype = swap32(getU32(buffer.add(off + 8)));
            if(cur_cpu_type == cputype && cur_cpu_subtype == cpusubtype){
                fileoffset = swap32(getU32(buffer.add(off + 12)));
                filesize = swap32(getU32(buffer.add(off + 16)));
                break;
            }
            off += 20;
        }
        if(fileoffset == 0 || filesize == 0) return;
        sys_lseek(fmodule, 0, SEEK_SET);
        sys_lseek(foldmodule, fileoffset, SEEK_SET);
        for(var i = 0; i < parseInt(filesize / BUFSIZE); i++) {
            sys_read(foldmodule, buffer, BUFSIZE);
            sys_write(fmodule, buffer, BUFSIZE);
        }
        if(filesize % BUFSIZE){
            sys_read(foldmodule, buffer, filesize % BUFSIZE);
            sys_write(fmodule, buffer, filesize % BUFSIZE);
        }
    } else {
        var readLen = 0;
        sys_lseek(foldmodule, 0, SEEK_SET);
        sys_lseek(fmodule, 0, SEEK_SET);
        while((readLen = sys_read(foldmodule, buffer, BUFSIZE)) > 0) {
            sys_write(fmodule, buffer, readLen);
        }
    }

    var ncmds = getU32(modbase.add(16));
    var off = size_of_mach_header;
    var offset_cryptid = -1;
    var crypt_off = 0;
    var crypt_size = 0;
    for (var i = 0; i < ncmds; i++) {
        var cmd = getU32(modbase.add(off));
        var cmdsize = getU32(modbase.add(off + 4));
        if (cmd == LC_ENCRYPTION_INFO || cmd == LC_ENCRYPTION_INFO_64) {
            offset_cryptid = off + 16;
            crypt_off = getU32(modbase.add(off + 8));
            crypt_size = getU32(modbase.add(off + 12));
        }
        off += cmdsize;
    }

    if (offset_cryptid != -1) {
        var tpbuf = malloc(8);
        putU64(tpbuf, 0);
        sys_lseek(fmodule, offset_cryptid, SEEK_SET);
        sys_write(fmodule, tpbuf, 4);
        sys_lseek(fmodule, crypt_off, SEEK_SET);
        
        if (crypt_size > 0 && crypt_off > 0) {
            // 核心修复：强制赋予解密内存块可读权限，防闪退
            Memory.protect(modbase.add(crypt_off), crypt_size, 'r-x');
            sys_write(fmodule, modbase.add(crypt_off), crypt_size);
        }
    }

    sys_close(fmodule);
    sys_close(foldmodule);
    return newmodpath;
}

function handleMessage(message) {
    console.log("[*] 收到 Python 指令，启动「V7 最终完美版」...");
    try {
        console.log(" -> [1/5] 正在初始化底层 C 函数...");
        initCoreFunctions(); 
        
        console.log(" -> [2/5] 准备遍历内存模块...");
        var app_path = "";
        var tmpmods = Process.enumerateModules();
        
        console.log(" -> [3/5] 遍历成功！找到 " + tmpmods.length + " 个模块，正在筛选...");
        for (var i = 0; i < tmpmods.length; i++) {
            var p = tmpmods[i].path;
            if (!p) continue; 
            var idx = p.indexOf(".app/");
            if (idx !== -1) {
                app_path = p.substring(0, idx + 4);
                break;
            }
        }
        
        if (!app_path) {
            send({type: "error", description: "严重错误：未发现 .app 路径！"});
            return;
        }
        console.log("    [发现目标] " + app_path);
        
        console.log(" -> [4/5] 开始提取并解密 Mach-O...");
        modules = getAllAppModules();
        for (var i = 0; i  < modules.length; i++) {
            console.log("    [正在砸壳] " + modules[i].path);
            var result = dumpModule(modules[i].path);
            if (result) {
                send({ dump: result, path: modules[i].path});
            }
        }
        
        console.log(" -> [5/5] 收尾，通知 Python 拉取文件...");
        send({app: app_path});
        send({done: "ok"});
        
    } catch(e) {
        send({type: "error", description: "V7 提取异常: " + e.message, stack: e.stack});
    }
    recv(handleMessage);
}

setTimeout(function() {
    recv(handleMessage);
}, 100);