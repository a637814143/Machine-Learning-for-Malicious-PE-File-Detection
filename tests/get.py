from flask import Flask, request, jsonify
import os
import tempfile
import shutil
import time
import frida

# ====================== Flask 应用初始化 ======================

app = Flask(__name__)

# 可选：限制上传大小，例如 10MB
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10MB


# ====================== Frida 脚本：Hook 文件/网络/注册表/进程 ======================

FRIDA_SCRIPT = r"""
function safeReadUtf16(ptr) {
    try { return ptr.isNull() ? "" : ptr.readUtf16String(); } catch (e) { return ""; }
}
function safeReadAnsi(ptr) {
    try { return ptr.isNull() ? "" : ptr.readAnsiString(); } catch (e) { return ""; }
}
function safeSend(evt, data) {
    send({ evt: evt, data: data });
}

// 将网络端口从网络字节序转换为主机字节序
function ntohs(port) {
    return ((port & 0xff) << 8) | ((port >> 8) & 0xff);
}

try {
    // ---------- 文件操作 ----------
    const fileAPIs = [
        // CreateFileW/A: args[0] = lpFileName
        { name: "CreateFileW", dll: "kernel32.dll", kind: "create" },
        { name: "CreateFileA", dll: "kernel32.dll", kind: "create" },
        // DeleteFileW/A: args[0] = lpFileName
        { name: "DeleteFileW", dll: "kernel32.dll", kind: "delete" },
        { name: "DeleteFileA", dll: "kernel32.dll", kind: "delete" },
        // WriteFile: args[0] = hFile, args[2] = nNumberOfBytesToWrite
        { name: "WriteFile",   dll: "kernel32.dll", kind: "write" }
    ];

    fileAPIs.forEach(function (api) {
        var addr = Module.findExportByName(api.dll, api.name);
        if (!addr) return;

        Interceptor.attach(addr, {
            onEnter: function (args) {
                var info = {
                    api: api.name,
                    kind: api.kind
                };

                if (api.kind === "create" || api.kind === "delete") {
                    if (api.name.endsWith("W"))
                        info.path = safeReadUtf16(args[0]);
                    else if (api.name.endsWith("A"))
                        info.path = safeReadAnsi(args[0]);
                } else if (api.kind === "write") {
                    info.bytesToWrite = args[2].toInt32();
                }

                safeSend("FileOperation", info);
            }
        });
    });

    // ---------- 网络通信 ----------
    var connectAddr = Module.findExportByName("ws2_32.dll", "connect");
    if (connectAddr) {
        Interceptor.attach(connectAddr, {
            onEnter: function (args) {
                try {
                    var sockaddr = args[1];
                    var family = sockaddr.readU16();
                    // 2 = AF_INET (IPv4)
                    if (family === 2) {
                        var portNetOrder = sockaddr.add(2).readU16();
                        var port = ntohs(portNetOrder);
                        var ip = sockaddr.add(4).readU8() + "." +
                                 sockaddr.add(5).readU8() + "." +
                                 sockaddr.add(6).readU8() + "." +
                                 sockaddr.add(7).readU8();
                        safeSend("NetworkConnect", {
                            ip: ip,
                            port: port,
                            family: "IPv4"
                        });
                    }
                } catch (e) {
                    safeSend("Error", "connect parse failed: " + e.message);
                }
            }
        });
    }

    // 简单 Hook send：只记录发送长度，不抓取内容
    var sendAddr = Module.findExportByName("ws2_32.dll", "send");
    if (sendAddr) {
        Interceptor.attach(sendAddr, {
            onEnter: function (args) {
                try {
                    var len = args[2].toInt32();
                    safeSend("NetworkSend", { bytes: len });
                } catch (e) {}
            }
        });
    }

    // ---------- 注册表操作 ----------
    const regAPIs = [
        { name: "RegCreateKeyExW", dll: "advapi32.dll", kind: "create" },
        { name: "RegSetValueExW",  dll: "advapi32.dll", kind: "set_value" },
        { name: "RegDeleteKeyW",   dll: "advapi32.dll", kind: "delete" }
    ];

    regAPIs.forEach(function (api) {
        var addr = Module.findExportByName(api.dll, api.name);
        if (!addr) return;

        Interceptor.attach(addr, {
            onEnter: function (args) {
                var info = { api: api.name, kind: api.kind };
                if (api.name === "RegCreateKeyExW" || api.name === "RegDeleteKeyW") {
                    info.subKey = safeReadUtf16(args[1]);
                } else if (api.name === "RegSetValueExW") {
                    info.valueName = safeReadUtf16(args[1]);
                    info.dataSize  = args[5].toInt32();
                }
                safeSend("RegistryOperation", info);
            }
        });
    });

    // ---------- 进程创建 ----------
    var createProc = Module.findExportByName("kernel32.dll", "CreateProcessW");
    if (createProc) {
        Interceptor.attach(createProc, {
            onEnter: function (args) {
                var appName = safeReadUtf16(args[0]);
                var cmdLine = safeReadUtf16(args[1]);
                safeSend("ProcessCreate", {
                    applicationName: appName,
                    cmdline: cmdLine
                });
            }
        });
    }

    safeSend("InitOK", "Hooks loaded successfully");
} catch (e) {
    safeSend("Error", e.message);
}
"""


# ====================== 动态分析主逻辑 ======================

def run_dynamic_analysis(exe_path, timeout=20, max_events=1000):
    """
    使用 Frida 对 exe_path 进行动态分析，最长运行 timeout 秒，
    每类事件最多记录 max_events 条，避免结果过大。
    """
    result = {
        "api_calls": [],
        "file_operations": [],
        "network_activity": [],
        "network_send": [],
        "registry_changes": [],
        "process_creations": [],
        "errors": [],
        # 简单统计汇总，后续可以作为“动态特征”
        "summary": {
            "file_op_count": 0,
            "net_connect_count": 0,
            "net_send_bytes": 0,
            "registry_op_count": 0,
            "process_create_count": 0
        }
    }

    pid = None
    session = None
    script = None

    def safe_append(lst, item):
        if len(lst) < max_events:
            lst.append(item)

    try:
        # 使用 Frida 启动并挂起目标进程
        pid = frida.spawn([exe_path])
        session = frida.attach(pid)
        script = session.create_script(FRIDA_SCRIPT)

        # 处理来自 Frida 脚本的消息
        def on_message(msg, data):
            if msg["type"] != "send":
                return
            payload = msg.get("payload") or {}
            evt = payload.get("evt")
            d = payload.get("data") or {}

            if evt == "FileOperation":
                safe_append(result["file_operations"], d)
                result["summary"]["file_op_count"] += 1

            elif evt == "NetworkConnect":
                safe_append(result["network_activity"], d)
                result["summary"]["net_connect_count"] += 1

            elif evt == "NetworkSend":
                safe_append(result["network_send"], d)
                result["summary"]["net_send_bytes"] += int(d.get("bytes", 0))

            elif evt == "RegistryOperation":
                safe_append(result["registry_changes"], d)
                result["summary"]["registry_op_count"] += 1

            elif evt == "ProcessCreate":
                safe_append(result["process_creations"], d)
                result["summary"]["process_create_count"] += 1

            elif evt == "Error":
                safe_append(result["errors"], d)
            else:
                safe_append(result["api_calls"], payload)

        script.on("message", on_message)
        script.load()

        # 恢复进程执行
        frida.resume(pid)

        start = time.time()
        # 简单轮询等待超时；也可以扩展为检测进程是否提前退出
        while time.time() - start < timeout:
            time.sleep(0.5)

    except Exception as e:
        result["errors"].append({"error": str(e), "where": "run_dynamic_analysis"})
    finally:
        # 清理 Frida 资源
        try:
            if script is not None:
                script.unload()
        except Exception:
            pass
        try:
            if session is not None:
                session.detach()
        except Exception:
            pass
        try:
            if pid is not None:
                frida.kill(pid)
        except Exception:
            pass

    return result


# ====================== Flask 上传接口 ======================

@app.route("/upload", methods=["POST"])
def upload_and_analyze():
    # 简单校验上传
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    f = request.files["file"]
    if not f.filename.lower().endswith(".exe"):
        return jsonify({"error": "Only .exe files supported"}), 400

    # 可选：从表单读取 timeout 和 max_events
    timeout = request.form.get("timeout", "20")
    max_events = request.form.get("max_events", "1000")
    try:
        timeout = max(1, min(int(timeout), 300))        # 限制 1~300 秒之间
        max_events = max(10, min(int(max_events), 5000))  # 限制 10~5000
    except ValueError:
        timeout = 20
        max_events = 1000

    temp_dir = tempfile.mkdtemp()
    path = os.path.join(temp_dir, f.filename)
    f.save(path)

    try:
        result = run_dynamic_analysis(path, timeout=timeout, max_events=max_events)
    finally:
        # 删除临时目录，避免样本堆积
        shutil.rmtree(temp_dir, ignore_errors=True)

    return jsonify(result)


if __name__ == "__main__":
    # ⚠️ 强烈建议只在安全的沙箱/虚拟机中运行
    # 默认监听 5000 端口，可按需修改
    app.run(host="0.0.0.0", port=5000, debug=False)
