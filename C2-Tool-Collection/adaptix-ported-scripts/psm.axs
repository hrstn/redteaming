var metadata = {
    name: "Psm",
    description: "Show detailed information from a specific process ID"
};

var cmd_psm = ax.create_command("psm", "Show detailed information from a specific process ID (loaded modules, TCP connections, etc.)", "psm <pid>");
cmd_psm.addArgInt("pid", true, "Target process ID");
cmd_psm.setPreHook(function (id, cmdline, parsed_json) {
    var pid        = parseInt(parsed_json["pid"]);
    var bof_params = ax.bof_pack("int", [pid]);
    var bof_path   = ax.script_dir() + "Psm." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, `Task: enumerate process ${pid}`);
});

var group_psm = ax.create_commands_group("Psm-BOF", [cmd_psm]);
ax.register_commands_group(group_psm, ["beacon", "gopher", "kharon"], ["windows"], []);
