var metadata = {
    name: "Domaininfo",
    description: "Enumerate domain information using Active Directory Domain Services"
};

var cmd_domaininfo = ax.create_command("domaininfo", "Enumerate domain information using Active Directory Domain Services", "domaininfo");
cmd_domaininfo.setPreHook(function (id, cmdline, parsed_json) {
    var bof_path = ax.script_dir() + "Domaininfo." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}"`, "Task: Domaininfo BOF by Outflank");
});

var group_domaininfo = ax.create_commands_group("Domaininfo-BOF", [cmd_domaininfo]);
ax.register_commands_group(group_domaininfo, ["beacon", "gopher", "kharon"], ["windows"], []);
