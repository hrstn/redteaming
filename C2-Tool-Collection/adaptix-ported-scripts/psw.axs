var metadata = {
    name: "Psw",
    description: "Show window titles from processes with active windows"
};

var cmd_psw = ax.create_command("psw", "Show window titles from processes with active windows", "psw");
cmd_psw.setPreHook(function (id, cmdline, parsed_json) {
    var bof_path = ax.script_dir() + "Psw." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}"`, "Task: list process window titles");
});

var group_psw = ax.create_commands_group("Psw-BOF", [cmd_psw]);
ax.register_commands_group(group_psw, ["beacon", "gopher", "kharon"], ["windows"], []);
