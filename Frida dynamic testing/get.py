# dynamic_frida_service_v2.py
# pip install flask frida
# 仅建议在虚拟机/沙箱中运行，且仅对你有授权的样本使用

from flask import Flask, request, jsonify
import os
import tempfile
import shutil
import time
import hashlib
import frida

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50MB


FRIDA_SCRIPT_TEMPLATE = r"""
'use strict';

const PROFILE="__PROFILE__";

const ENABLE = {
  fast: PROFILE==="fast",
  balanced: PROFILE==="balanced",
  deep: PROFILE==="deep"
};

const CONFIG = {
  batchSize: ENABLE.deep ? 60 : (ENABLE.balanced ? 120 : 160),
  flushMs: ENABLE.deep ? 120 : (ENABLE.balanced ? 180 : 250),
  maxStringLen: 320,
  // deep抓调用栈很容易拖慢/不稳定，你如果还卡就把这里改成0
  maxStackDepth: ENABLE.deep ? 0 : 0,
};

function now(){ return Date.now(); }
function base(){
  return { ts: now(), pid: Process.id, tid: Process.getCurrentThreadId() };
}

function safeReadUtf16(p){
  try { return p.isNull() ? "" : p.readUtf16String(CONFIG.maxStringLen); } catch(e){ return ""; }
}
function safeReadAnsi(p){
  try { return p.isNull() ? "" : p.readAnsiString(CONFIG.maxStringLen); } catch(e){ return ""; }
}
function safeReadStr(p, wide){ return wide ? safeReadUtf16(p) : safeReadAnsi(p); }

function ntohs(port){ return ((port & 0xff) << 8) | ((port >> 8) & 0xff); }

function parseSockaddr(sa){
  try{
    if(sa.isNull()) return null;
    const family = sa.readU16();
    if(family === 2){
      const port = ntohs(sa.add(2).readU16());
      const ip = sa.add(4).readU8()+"."+sa.add(5).readU8()+"."+sa.add(6).readU8()+"."+sa.add(7).readU8();
      return { family:"IPv4", ip: ip, port: port };
    }
    if(family === 23){
      const port = ntohs(sa.add(2).readU16());
      return { family:"IPv6", port: port };
    }
    return { family:"UNKNOWN", rawFamily: family };
  }catch(e){
    return { family:"PARSE_ERROR", error: e.message };
  }
}

function findExport(dlls, name){
  for(let i=0;i<dlls.length;i++){
    const a = Module.findExportByName(dlls[i], name);
    if(a) return a;
  }
  return null;
}

function isInvalidHandle(h){
  try { return h.isNull() || h.equals(ptr("-1")); } catch(e){ return false; }
}

// ===== 批量队列 + 强制flush =====
let Q = [];
let _flushing = false;

const fileHandles = {}; // handle->path
const sockPeers  = {}; // socket->peer

const agg = {
  file: { readBytes:0, readCalls:0, writeBytes:0, writeCalls:0, handles:{} },
  net:  { sendBytes:0, sendCalls:0, recvBytes:0, recvCalls:0, sockets:{} },
};

function addFileAgg(h, dir, bytes){
  const k = String(h);
  if(!agg.file.handles[k]) agg.file.handles[k] = { path: fileHandles[k] || "", readBytes:0, readCalls:0, writeBytes:0, writeCalls:0 };
  if(dir==="read"){
    agg.file.readBytes += bytes; agg.file.readCalls += 1;
    agg.file.handles[k].readBytes += bytes; agg.file.handles[k].readCalls += 1;
  }else{
    agg.file.writeBytes += bytes; agg.file.writeCalls += 1;
    agg.file.handles[k].writeBytes += bytes; agg.file.handles[k].writeCalls += 1;
  }
  agg.file.handles[k].path = fileHandles[k] || agg.file.handles[k].path || "";
}

function addNetAgg(s, dir, bytes, peer){
  const k = String(s);
  if(!agg.net.sockets[k]) agg.net.sockets[k] = { peer: peer||null, sendBytes:0, sendCalls:0, recvBytes:0, recvCalls:0 };
  if(dir==="send"){
    agg.net.sendBytes += bytes; agg.net.sendCalls += 1;
    agg.net.sockets[k].sendBytes += bytes; agg.net.sockets[k].sendCalls += 1;
  }else{
    agg.net.recvBytes += bytes; agg.net.recvCalls += 1;
    agg.net.sockets[k].recvBytes += bytes; agg.net.sockets[k].recvCalls += 1;
  }
  if(peer) agg.net.sockets[k].peer = peer;
}

function topNMap(obj, scoreFn, limit){
  const arr = [];
  for(const k in obj){
    const v = obj[k];
    arr.push({ id:k, score: scoreFn(v), data: v });
  }
  arr.sort((a,b)=>b.score-a.score);
  return arr.slice(0, limit).map(x => Object.assign({ id:x.id }, x.data));
}

function emit(evt, obj){
  Q.push(Object.assign(base(), { evt: evt }, obj || {}));
  if(!_flushing && Q.length >= CONFIG.batchSize) flush();
}

function flushAgg(){
  if(ENABLE.fast) return;

  if(agg.file.readCalls + agg.file.writeCalls > 0){
    emit("File.Summary", {
      readCalls: agg.file.readCalls,
      readBytes: agg.file.readBytes,
      writeCalls: agg.file.writeCalls,
      writeBytes: agg.file.writeBytes,
      topHandles: topNMap(agg.file.handles, v => (v.readBytes+v.writeBytes), 10),
    });
    agg.file.readBytes=0; agg.file.readCalls=0; agg.file.writeBytes=0; agg.file.writeCalls=0; agg.file.handles={};
  }

  if(agg.net.sendCalls + agg.net.recvCalls > 0){
    emit("Net.Summary", {
      sendCalls: agg.net.sendCalls,
      sendBytes: agg.net.sendBytes,
      recvCalls: agg.net.recvCalls,
      recvBytes: agg.net.recvBytes,
      topSockets: topNMap(agg.net.sockets, v => (v.sendBytes+v.recvBytes), 10),
    });
    agg.net.sendBytes=0; agg.net.sendCalls=0; agg.net.recvBytes=0; agg.net.recvCalls=0; agg.net.sockets={};
  }
}

function flush(){
  if(_flushing) return;
  _flushing = true;
  try{
    flushAgg();
    if(Q.length === 0) return;
    send({ evt: "Batch", data: Q });
    Q = [];
  } finally {
    _flushing = false;
  }
}

setInterval(flush, CONFIG.flushMs);

// 给Python用：结束前强制flush，避免短进程丢事件
rpc.exports = {
  flush: function(){
    try{ flush(); return true; }catch(e){ return false; }
  }
};

// ================= 文件行为 =================
(function(){
  ["W","A"].forEach(function(sfx){
    const wide = (sfx==="W");
    const create = findExport(["kernel32.dll","kernelbase.dll"], "CreateFile"+sfx);
    if(create){
      Interceptor.attach(create,{
        onEnter:function(args){
          this.path = safeReadStr(args[0], wide);
          emit("File.Create",{
            api:"CreateFile"+sfx,
            path:this.path,
            desiredAccess: args[1].toUInt32(),
            shareMode: args[2].toUInt32(),
            disposition: args[4].toUInt32(),
            flags: args[5].toUInt32()
          });
        },
        onLeave:function(ret){
          if(!isInvalidHandle(ret) && this.path){
            fileHandles[ret.toString()] = this.path;
          }
        }
      });
    }

    const del = findExport(["kernel32.dll","kernelbase.dll"], "DeleteFile"+sfx);
    if(del){
      Interceptor.attach(del,{
        onEnter:function(args){
          emit("File.Delete",{ api:"DeleteFile"+sfx, path: safeReadStr(args[0], wide) });
        }
      });
    }

    const cp = findExport(["kernel32.dll","kernelbase.dll"], "CopyFile"+sfx);
    if(cp){
      Interceptor.attach(cp,{
        onEnter:function(args){
          emit("File.Copy",{ api:"CopyFile"+sfx, src:safeReadStr(args[0],wide), dst:safeReadStr(args[1],wide) });
        }
      });
    }

    const mkdir = findExport(["kernel32.dll","kernelbase.dll"], "CreateDirectory"+sfx);
    if(mkdir){
      Interceptor.attach(mkdir,{
        onEnter:function(args){
          emit("File.Mkdir",{ api:"CreateDirectory"+sfx, path:safeReadStr(args[0],wide) });
        }
      });
    }
  });

  // ReadFile/WriteFile：balanced聚合，deep逐条(但仍建议聚合，防止巨大)
  const rf = findExport(["kernel32.dll","kernelbase.dll"], "ReadFile");
  if(rf && !ENABLE.fast){
    Interceptor.attach(rf,{
      onEnter:function(args){
        const h = args[0].toString();
        const n = args[2].toUInt32();
        if(ENABLE.deep){
          emit("File.Read",{ api:"ReadFile", handle:h, path:fileHandles[h]||"", bytesRequested:n });
        }else{
          addFileAgg(h, "read", n);
        }
      }
    });
  }

  const wf = findExport(["kernel32.dll","kernelbase.dll"], "WriteFile");
  if(wf && !ENABLE.fast){
    Interceptor.attach(wf,{
      onEnter:function(args){
        const h = args[0].toString();
        const n = args[2].toUInt32();
        if(ENABLE.deep){
          emit("File.Write",{ api:"WriteFile", handle:h, path:fileHandles[h]||"", bytesToWrite:n });
        }else{
          addFileAgg(h, "write", n);
        }
      }
    });
  }

  const ch = findExport(["kernel32.dll","kernelbase.dll"], "CloseHandle");
  if(ch){
    Interceptor.attach(ch,{
      onEnter:function(args){
        const h = args[0].toString();
        if(fileHandles[h]) delete fileHandles[h];
      }
    });
  }
})();

// ================= 网络行为 =================
(function(){
  const conn = findExport(["ws2_32.dll"], "connect");
  if(conn){
    Interceptor.attach(conn,{
      onEnter:function(args){
        const s = args[0].toString();
        const peer = parseSockaddr(args[1]);
        if(peer && peer.ip) sockPeers[s] = peer;
        emit("Net.Connect",{ api:"connect", socket:s, peer: peer });
      }
    });
  }

  const gai = findExport(["ws2_32.dll"], "getaddrinfo");
  if(gai){
    Interceptor.attach(gai,{
      onEnter:function(args){
        emit("Net.DNS.getaddrinfo",{ api:"getaddrinfo", node: safeReadAnsi(args[0]), service: safeReadAnsi(args[1]) });
      }
    });
  }

  // send/recv：balanced聚合，deep逐条
  const sSend = findExport(["ws2_32.dll"], "send");
  if(sSend && !ENABLE.fast){
    Interceptor.attach(sSend,{
      onEnter:function(args){
        const s = args[0].toString();
        const n = args[2].toInt32();
        const peer = sockPeers[s] || null;
        if(ENABLE.deep){
          emit("Net.Send",{ api:"send", socket:s, bytes:n, peer: peer });
        }else{
          addNetAgg(s, "send", Math.max(0,n), peer);
        }
      }
    });
  }

  const sRecv = findExport(["ws2_32.dll"], "recv");
  if(sRecv && !ENABLE.fast){
    Interceptor.attach(sRecv,{
      onEnter:function(args){
        const s = args[0].toString();
        const n = args[2].toInt32();
        const peer = sockPeers[s] || null;
        if(ENABLE.deep){
          emit("Net.Recv",{ api:"recv", socket:s, bytesRequested:n, peer: peer });
        }else{
          addNetAgg(s, "recv", Math.max(0,n), peer);
        }
      }
    });
  }

  // WinINet/WinHTTP 低频网络
  const openUrl = findExport(["wininet.dll"], "InternetOpenUrlW");
  if(openUrl){
    Interceptor.attach(openUrl,{
      onEnter:function(args){
        emit("Net.WinINet.OpenUrl",{ api:"InternetOpenUrlW", url: safeReadUtf16(args[1]) });
      }
    });
  }
  const httpSend = findExport(["wininet.dll"], "HttpSendRequestW");
  if(httpSend){
    Interceptor.attach(httpSend,{
      onEnter:function(args){
        emit("Net.WinINet.HttpSend",{ api:"HttpSendRequestW", hRequest: args[0].toString() });
      }
    });
  }
  const whSend = findExport(["winhttp.dll"], "WinHttpSendRequest");
  if(whSend){
    Interceptor.attach(whSend,{
      onEnter:function(args){
        emit("Net.WinHTTP.SendRequest",{ api:"WinHttpSendRequest", hRequest: args[0].toString() });
      }
    });
  }
})();

// ================= 注册表行为 =================
(function(){
  const openK = findExport(["advapi32.dll"], "RegOpenKeyExW");
  if(openK){
    Interceptor.attach(openK,{
      onEnter:function(args){
        emit("Reg.OpenKey",{ api:"RegOpenKeyExW", subKey: safeReadUtf16(args[1]), sam: args[3].toUInt32() });
      }
    });
  }
  const createK = findExport(["advapi32.dll"], "RegCreateKeyExW");
  if(createK){
    Interceptor.attach(createK,{
      onEnter:function(args){
        emit("Reg.CreateKey",{ api:"RegCreateKeyExW", subKey: safeReadUtf16(args[1]) });
      }
    });
  }
  const setV = findExport(["advapi32.dll"], "RegSetValueExW");
  if(setV){
    Interceptor.attach(setV,{
      onEnter:function(args){
        emit("Reg.SetValue",{ api:"RegSetValueExW", valueName: safeReadUtf16(args[1]), type: args[3].toUInt32(), dataSize: args[5].toUInt32() });
      }
    });
  }
})();

// ================= 进程/命令执行(重点补齐) =================
(function(){
  // CreateProcess A/W
  ["W","A"].forEach(function(sfx){
    const wide = (sfx==="W");
    const api = "CreateProcess"+sfx;
    const addr = findExport(["kernel32.dll","kernelbase.dll"], api);
    if(addr){
      Interceptor.attach(addr,{
        onEnter:function(args){
          emit("Proc.Create",{
            api: api,
            applicationName: safeReadStr(args[0], wide),
            cmdline: safeReadStr(args[1], wide),
            flags: args[5].toUInt32()
          });
        }
      });
    }
  });

  // ShellExecute A/W
  ["W","A"].forEach(function(sfx){
    const wide = (sfx==="W");
    const api = "ShellExecute"+sfx;
    const addr = findExport(["shell32.dll"], api);
    if(addr){
      Interceptor.attach(addr,{
        onEnter:function(args){
          emit("Proc.ShellExecute",{
            api: api,
            operation: safeReadStr(args[1], wide),
            file: safeReadStr(args[2], wide),
            parameters: safeReadStr(args[3], wide),
            directory: safeReadStr(args[4], wide),
            showCmd: args[5].toInt32()
          });
        }
      });
    }
  });

  // WinExec
  const winexec = findExport(["kernel32.dll","kernelbase.dll"], "WinExec");
  if(winexec){
    Interceptor.attach(winexec,{
      onEnter:function(args){
        emit("Proc.WinExec",{ api:"WinExec", cmd: safeReadAnsi(args[0]), showCmd: args[1].toUInt32() });
      }
    });
  }

  // C运行库的system/_wsystem（很多MinGW程序会走这里）
  const sys = findExport(["msvcrt.dll","ucrtbase.dll"], "system");
  if(sys){
    Interceptor.attach(sys,{
      onEnter:function(args){
        emit("Proc.CRT.system",{ api:"system", cmd: safeReadAnsi(args[0]) });
      }
    });
  }
  const wsys = findExport(["msvcrt.dll","ucrtbase.dll"], "_wsystem");
  if(wsys){
    Interceptor.attach(wsys,{
      onEnter:function(args){
        emit("Proc.CRT._wsystem",{ api:"_wsystem", cmd: safeReadUtf16(args[0]) });
      }
    });
  }
})();

emit("InitOK",{ profile: PROFILE });
"""


def sha256_file(file_path: str, chunk: int = 4 * 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def run_dynamic_analysis(exe_path: str, timeout: int = 20, max_events: int = 3000, profile: str = "balanced") -> dict:
    profile = (profile or "balanced").lower()
    if profile not in ("fast", "balanced", "deep"):
        profile = "balanced"

    result = {
        "meta": {
            "exe_name": os.path.basename(exe_path),
            "sha256": "",
            "profile": profile,
            "timeout": int(timeout),
            "max_events": int(max_events),
            "start_time": time.time(),
            "end_time": None,
        },
        "events": {
            "file": [],
            "net": [],
            "reg": [],
            "proc": [],
            "summary": [],
            "misc": [],
            "error": [],
        },
        "summary": {
            "file_count": 0,
            "net_count": 0,
            "reg_count": 0,
            "proc_count": 0,
            "summary_count": 0,
            "misc_count": 0,
            "error_count": 0,
        }
    }

    def safe_append(cat: str, item: dict):
        if len(result["events"][cat]) < max_events:
            result["events"][cat].append(item)

    def route_event(e: dict):
        name = str(e.get("evt", ""))

        if name in ("File.Summary", "Net.Summary"):
            result["summary"]["summary_count"] += 1
            safe_append("summary", e)
            return

        if name.startswith("File."):
            result["summary"]["file_count"] += 1
            safe_append("file", e)
        elif name.startswith("Net."):
            result["summary"]["net_count"] += 1
            safe_append("net", e)
        elif name.startswith("Reg."):
            result["summary"]["reg_count"] += 1
            safe_append("reg", e)
        elif name.startswith("Proc."):
            result["summary"]["proc_count"] += 1
            safe_append("proc", e)
        elif name == "Error":
            result["summary"]["error_count"] += 1
            safe_append("error", e)
        else:
            result["summary"]["misc_count"] += 1
            safe_append("misc", e)

    device = None
    pid = None
    session = None
    script = None

    try:
        result["meta"]["sha256"] = sha256_file(exe_path)
        device = frida.get_local_device()

        pid = device.spawn([exe_path])
        session = device.attach(pid)

        script_source = FRIDA_SCRIPT_TEMPLATE.replace("__PROFILE__", profile)
        script = session.create_script(script_source)

        def on_message(msg, data):
            if msg.get("type") != "send":
                return
            payload = msg.get("payload") or {}
            evt_type = payload.get("evt")
            if evt_type == "Batch":
                batch = payload.get("data") or []
                for item in batch:
                    if isinstance(item, dict):
                        route_event(item)
                return
            if isinstance(payload, dict):
                route_event(payload)

        script.on("message", on_message)
        script.load()

        device.resume(pid)

        start = time.time()
        while time.time() - start < timeout:
            time.sleep(0.15)

        # 关键：结束前强制flush，避免短进程漏事件
        try:
            script.exports_sync.flush()
            time.sleep(0.2)
        except Exception:
            pass

    except Exception as e:
        result["summary"]["error_count"] += 1
        safe_append("error", {"evt": "Error", "where": "run_dynamic_analysis", "error": str(e)})
    finally:
        try:
            if script is not None:
                try:
                    script.exports_sync.flush()
                    time.sleep(0.1)
                except Exception:
                    pass
                script.unload()
        except Exception:
            pass
        try:
            if session is not None:
                session.detach()
        except Exception:
            pass
        try:
            if device is not None and pid is not None:
                device.kill(pid)
        except Exception:
            pass

        result["meta"]["end_time"] = time.time()

    return result


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "time": time.time()})

@app.route("/upload", methods=["POST"])
def upload_and_analyze():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    f = request.files["file"]
    if not f.filename.lower().endswith(".exe"):
        return jsonify({"error": "Only .exe supported"}), 400

    timeout = request.form.get("timeout", "20")
    max_events = request.form.get("max_events", "3000")
    profile = request.form.get("profile", "deep")  # fast/balanced/deep

    try:
        timeout = max(1, min(int(timeout), 180))
        max_events = max(200, min(int(max_events), 12000))
    except ValueError:
        timeout = 20
        max_events = 3000

    temp_dir = tempfile.mkdtemp()
    path = os.path.join(temp_dir, f.filename)
    f.save(path)

    try:
        result = run_dynamic_analysis(path, timeout=timeout, max_events=max_events, profile=profile)
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

    return jsonify(result)


if __name__ == "__main__":
    # 端口对齐：你GUI报错连的是5002，这里默认就是5002
    app.run(host="0.0.0.0", port=5007, debug=False)
