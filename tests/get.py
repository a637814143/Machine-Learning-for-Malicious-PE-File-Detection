from flask import Flask, request, jsonify
import os
import tempfile
import shutil
import time
import frida


app = Flask(__name__)

# ---------- Frida 脚本：Hook 文件 / 网络 / 注册表 / 进程 ----------
FRIDA_SCRIPT = r"""
function safeReadUtf16(ptr){ try{return ptr.readUtf16String();}catch(e){return "";}}
function safeReadAnsi(ptr){ try{return ptr.readAnsiString();}catch(e){return "";}}
function safeSend(evt,data){ send({evt:evt,data:data}); }

try {
    // 文件操作
    const fileAPIs = [
        ["CreateFileW","kernel32.dll"],
        ["CreateFileA","kernel32.dll"],
        ["DeleteFileW","kernel32.dll"],
        ["DeleteFileA","kernel32.dll"],
        ["WriteFile","kernel32.dll"]
    ];
    fileAPIs.forEach(function(x){
        var addr = Module.findExportByName(x[1],x[0]);
        if(addr){
            Interceptor.attach(addr,{
                onEnter:function(args){
                    var info = {};
                    if(x[0].endsWith("W")) info.path = safeReadUtf16(args[0]);
                    else if(x[0].endsWith("A")) info.path = safeReadAnsi(args[0]);
                    info.api = x[0];
                    safeSend("FileOperation",info);
                }
            });
        }
    });

    // 网络通信
    var connectAddr = Module.findExportByName("ws2_32.dll", "connect");
    if(connectAddr){
        Interceptor.attach(connectAddr,{
            onEnter:function(args){
                try{
                    var sockaddr = args[1];
                    var port = sockaddr.add(2).readU16();
                    var ip = sockaddr.add(4).readU8()+"."+sockaddr.add(5).readU8()+"."+sockaddr.add(6).readU8()+"."+sockaddr.add(7).readU8();
                    safeSend("NetworkConnect",{ip:ip,port:port});
                }catch(e){}
            }
        });
    }

    // 注册表操作
    const regAPIs = [
        ["RegCreateKeyExW","advapi32.dll"],
        ["RegSetValueExW","advapi32.dll"],
        ["RegDeleteKeyW","advapi32.dll"]
    ];
    regAPIs.forEach(function(x){
        var addr = Module.findExportByName(x[1],x[0]);
        if(addr){
            Interceptor.attach(addr,{
                onEnter:function(args){
                    var name = safeReadUtf16(args[1]);
                    safeSend("RegistryOperation",{api:x[0],key:name});
                }
            });
        }
    });

    // 进程创建
    var createProc = Module.findExportByName("kernel32.dll","CreateProcessW");
    if(createProc){
        Interceptor.attach(createProc,{
            onEnter:function(args){
                var cmd = safeReadUtf16(args[1]);
                safeSend("ProcessCreate",{cmdline:cmd});
            }
        });
    }

    safeSend("InitOK","Hooks loaded successfully");
}catch(e){
    safeSend("Error",e.message);
}
"""

# ---------- 运行并分析 ----------
def run_dynamic_analysis(exe_path, timeout=20):
    result = {
        "api_calls": [],
        "file_operations": [],
        "network_activity": [],
        "registry_changes": [],
        "process_creations": [],
        "errors": []
    }

    try:
        pid = frida.spawn([exe_path])
        session = frida.attach(pid)
        script = session.create_script(FRIDA_SCRIPT)

        def on_message(msg, data):
            if msg["type"] == "send":
                payload = msg["payload"]
                evt = payload.get("evt")
                data = payload.get("data")
                if evt == "FileOperation":
                    result["file_operations"].append(data)
                elif evt == "NetworkConnect":
                    result["network_activity"].append(data)
                elif evt == "RegistryOperation":
                    result["registry_changes"].append(data)
                elif evt == "ProcessCreate":
                    result["process_creations"].append(data)
                elif evt == "Error":
                    result["errors"].append(data)
                else:
                    result["api_calls"].append(payload)
        script.on("message", on_message)
        script.load()
        frida.resume(pid)

        # 运行一段时间
        start = time.time()
        while time.time() - start < timeout:
            time.sleep(1)

    except Exception as e:
        result["errors"].append(str(e))
    finally:
        try:
            frida.kill(pid)
        except Exception:
            pass

    return result


# ---------- Flask 接口 ----------
@app.route("/upload", methods=["POST"])
def upload_and_analyze():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    f = request.files["file"]
    if not f.filename.lower().endswith(".exe"):
        return jsonify({"error": "Only .exe files supported"}), 400

    temp_dir = tempfile.mkdtemp()
    path = os.path.join(temp_dir, f.filename)
    f.save(path)

    try:
        result = run_dynamic_analysis(path)
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

    return jsonify(result)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
