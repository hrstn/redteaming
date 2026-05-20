var metadata = {
    name: "FindObjects",
    description: "Enumerate processes for specific loaded modules or process handles"
};

var cmd_findprochandle = ax.create_command("FindProcHandle", "Find processes that hold a handle to the specified process", "FindProcHandle <process.exe>");
cmd_findprochandle.addArgString("process", true, "Target process name to search handles for (e.g. lsass.exe)");
cmd_findprochandle.setPreHook(function (id, cmdline, parsed_json) {
    var process    = parsed_json["process"];
    var bof_params = ax.bof_pack("wstr", [process]);
    var bof_path   = ax.script_dir() + "FindProcHandle." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, `Task: find processes with open handle to ${process}`);
});

var cmd_findmodule = ax.create_command("FindModule", "Find processes that have the specified module loaded", "FindModule <module.dll>");
cmd_findmodule.addArgString("module", true, "Module name to search for (e.g. clr.dll)");
cmd_findmodule.setPreHook(function (id, cmdline, parsed_json) {
    var module     = parsed_json["module"];
    var bof_params = ax.bof_pack("wstr", [module]);
    var bof_path   = ax.script_dir() + "FindModule." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, `Task: find processes with module ${module}`);
});

var group_findobjects = ax.create_commands_group("FindObjects-BOF", [cmd_findprochandle, cmd_findmodule]);
ax.register_commands_group(group_findobjects, ["beacon", "gopher", "kharon"], ["windows"], []);
