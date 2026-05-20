var metadata = {
    name: "Winver",
    description: "Display Windows version, build number, and Update Build Revision"
};

var cmd_winver = ax.create_command("winver", "Display the Windows version, build number, and Update Build Revision (UBR)", "winver");
cmd_winver.setPreHook(function (id, cmdline, parsed_json) {
    var bof_path = ax.script_dir() + "Winver." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}"`, "Task: display Windows version info");
});

var group_winver = ax.create_commands_group("Winver-BOF", [cmd_winver]);
ax.register_commands_group(group_winver, ["beacon", "gopher", "kharon"], ["windows"], []);
