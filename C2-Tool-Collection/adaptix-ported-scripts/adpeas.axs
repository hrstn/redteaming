var metadata = {
    name: "adPEAS",
    description: "Active Directory enumeration BOF - covers DCs, password policy, trusts, Kerberoast, ASREPRoast, delegation, privileged groups, ADCS"
};

/*
 * adPEAS BOF - Automated Active Directory Enumeration
 *
 * Sections enumerated automatically (no arguments required):
 *   [1]  Domain Controllers
 *   [2]  krbtgt account (password age)
 *   [3]  Default Password Policy
 *   [4]  Fine-Grained Password Policies (FGPP/PSO)
 *   [5]  Domain Trusts
 *   [6]  AS-REP Roastable Accounts (DONT_REQ_PREAUTH)
 *   [7]  Kerberoastable Accounts (SPN set, enabled)
 *   [8]  Unconstrained Delegation (non-DCs)
 *   [9]  Constrained Delegation (msDS-AllowedToDelegateTo)
 *   [10] Resource-Based Constrained Delegation (RBCD)
 *   [11] Privileged Group Members (DA, EA, SA, Admins, Operators, DnsAdmins)
 *   [12] Accounts with possible password in description
 *   [13] ADCS Enrollment Services (Certificate Authorities)
 *
 * Usage:
 *   adpeas               — use auto-discovered DC (current domain context)
 *   adpeas -s dc1.corp   — target a specific Domain Controller
 */

var cmd_adpeas = ax.create_command(
    "adpeas",
    "Enumerate Active Directory security posture (DCs, password policy, Kerberoast, delegation, ADCS, ...)",
    "adpeas [-s <dc>]"
);

cmd_adpeas.addArgFlagString("-s", "server", "Target Domain Controller (optional, uses current domain if omitted)", "");

cmd_adpeas.setPreHook(function (id, cmdline, parsed_json) {
    var server   = parsed_json["server"] || "";
    var bof_path = ax.script_dir() + "adPEAS." + ax.arch(id) + ".o";
    var bof_params = ax.bof_pack("wstr", [server]);
    var target_msg = server !== "" ? "targeting DC: " + server : "auto-discovering DC";
    ax.execute_alias(id, cmdline,
        `execute bof "${bof_path}" ${bof_params}`,
        `Task: adPEAS AD enumeration BOF (${target_msg})`
    );
});

var group_adpeas = ax.create_commands_group("adPEAS-BOF", [cmd_adpeas]);
ax.register_commands_group(group_adpeas, ["beacon", "gopher", "kharon"], ["windows"], []);
