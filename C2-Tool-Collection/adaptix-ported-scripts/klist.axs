var metadata = {
    name: "Klist",
    description: "Display, purge, or request cached Kerberos tickets"
};

var cmd_klist = ax.create_command("klist", "Display, purge, or request cached Kerberos tickets", "klist [purge | get <SPN>]");
cmd_klist.addArgString("command", false, "Optional action: purge or get");
cmd_klist.addArgString("spn",     false, "Service Principal Name (required with 'get')");
cmd_klist.setPreHook(function (id, cmdline, parsed_json) {
    var cmd      = parsed_json["command"] || "";
    var spn      = parsed_json["spn"]     || "";
    var bof_path = ax.script_dir() + "Klist." + ax.arch(id) + ".o";

    if (cmd === "get") {
        var bof_params = ax.bof_pack("wstr,wstr", ["get", spn]);
        ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, `Task: request TGS ticket for ${spn}`);
    } else if (cmd === "purge") {
        var bof_params = ax.bof_pack("wstr", ["purge"]);
        ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "Task: purge all Kerberos tickets");
    } else {
        ax.execute_alias(id, cmdline, `execute bof "${bof_path}"`, "Task: enumerate cached Kerberos tickets");
    }
});

var group_klist = ax.create_commands_group("Klist-BOF", [cmd_klist]);
ax.register_commands_group(group_klist, ["beacon", "gopher", "kharon"], ["windows"], []);
