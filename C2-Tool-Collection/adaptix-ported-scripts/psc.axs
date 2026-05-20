var metadata = {
    name: "Psc",
    description: "Show processes with established TCP and RDP connections"
};

var cmd_psc = ax.create_command("psc", "Show detailed information from processes with established TCP and RDP connections", "psc");
cmd_psc.setPreHook(function (id, cmdline, parsed_json) {
    var bof_path = ax.script_dir() + "Psc." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}"`, "Task: list processes with established TCP/RDP connections");
});

var group_psc = ax.create_commands_group("Psc-BOF", [cmd_psc]);
ax.register_commands_group(group_psc, ["beacon", "gopher", "kharon"], ["windows"], []);
