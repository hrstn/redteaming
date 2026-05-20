var metadata = {
    name: "Psk",
    description: "Show Windows kernel info and loaded driver modules"
};

var cmd_psk = ax.create_command("psk", "Show detailed information from the Windows kernel and loaded driver modules", "psk");
cmd_psk.setPreHook(function (id, cmdline, parsed_json) {
    var bof_path = ax.script_dir() + "Psk." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}"`, "Task: enumerate Windows kernel and driver modules");
});

var group_psk = ax.create_commands_group("Psk-BOF", [cmd_psk]);
ax.register_commands_group(group_psk, ["beacon", "gopher", "kharon"], ["windows"], []);
