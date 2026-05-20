var metadata = {
    name: "ReconAD",
    description: "Query Active Directory objects and attributes via ADSI"
};

// All four commands use the same BOF (ReconAD.{arch}.o).
// The first packed argument is the query mode: custom, users, groups, computers.
// Pack format: wstr,wstr,wstr,int,int,wstr = mode, object/filter, attributes, maxcount, usegc, server

function _reconad_hook(mode, id, cmdline, parsed_json) {
    var object_or_filter = parsed_json["object"] || parsed_json["filter"] || "";
    var attr   = parsed_json["attributes"] || "-all";
    var count  = parseInt(parsed_json["maxresults"] || "0", 10);
    var usegc  = parsed_json["-gc"] ? 1 : 0;
    var server = parsed_json["server"] || "-noserver";

    var bof_params = ax.bof_pack("wstr,wstr,wstr,int,int,wstr", [mode, object_or_filter, attr, count, usegc, server]);
    var bof_path   = ax.script_dir() + "ReconAD." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, `Task: ReconAD [${mode}] ${object_or_filter}`);
}

// ReconAD — custom LDAP filter
var cmd_reconad = ax.create_command("ReconAD", "Query Active Directory objects using a custom LDAP filter", "ReconAD <ldap-filter> [-a attributes] [-n maxresults] [-gc] [-s server:port]");
cmd_reconad.addArgString("filter", true, "LDAP filter expression (e.g. (&(objectClass=user)(sAMAccountName=*admin*)))");
cmd_reconad.addArgFlagString("-a", "attributes", "Comma-separated LDAP attributes, or -all", "-all");
cmd_reconad.addArgFlagString("-n", "maxresults", "Max result count (0 = unlimited)", "0");
cmd_reconad.addArgBool("-gc", "Search the Global Catalogue instead of LDAP");
cmd_reconad.addArgFlagString("-s", "server", "Optional DC server:port for explicit binding", "-noserver");
cmd_reconad.setPreHook(function (id, cmdline, parsed_json) { _reconad_hook("custom",    id, cmdline, parsed_json); });

// ReconAD-Users
var cmd_reconad_users = ax.create_command("ReconAD-Users", "Query Active Directory user objects and attributes", "ReconAD-Users <username> [-a attributes] [-n maxresults] [-gc] [-s server:port]");
cmd_reconad_users.addArgString("object", true, "Username or wildcard (e.g. *admin*)");
cmd_reconad_users.addArgFlagString("-a", "attributes", "Comma-separated LDAP attributes, or -all", "-all");
cmd_reconad_users.addArgFlagString("-n", "maxresults", "Max result count (0 = unlimited)", "0");
cmd_reconad_users.addArgBool("-gc", "Search the Global Catalogue instead of LDAP");
cmd_reconad_users.addArgFlagString("-s", "server", "Optional DC server:port for explicit binding", "-noserver");
cmd_reconad_users.setPreHook(function (id, cmdline, parsed_json) { _reconad_hook("users",     id, cmdline, parsed_json); });

// ReconAD-Computers
var cmd_reconad_computers = ax.create_command("ReconAD-Computers", "Query Active Directory computer objects and attributes", "ReconAD-Computers <computername> [-a attributes] [-n maxresults] [-gc] [-s server:port]");
cmd_reconad_computers.addArgString("object", true, "Computer name or wildcard (e.g. *dc*)");
cmd_reconad_computers.addArgFlagString("-a", "attributes", "Comma-separated LDAP attributes, or -all", "-all");
cmd_reconad_computers.addArgFlagString("-n", "maxresults", "Max result count (0 = unlimited)", "0");
cmd_reconad_computers.addArgBool("-gc", "Search the Global Catalogue instead of LDAP");
cmd_reconad_computers.addArgFlagString("-s", "server", "Optional DC server:port for explicit binding", "-noserver");
cmd_reconad_computers.setPreHook(function (id, cmdline, parsed_json) { _reconad_hook("computers", id, cmdline, parsed_json); });

// ReconAD-Groups
var cmd_reconad_groups = ax.create_command("ReconAD-Groups", "Query Active Directory group objects and attributes", "ReconAD-Groups <groupname> [-a attributes] [-n maxresults] [-gc] [-s server:port]");
cmd_reconad_groups.addArgString("object", true, "Group name or wildcard (e.g. \"Domain Admins\")");
cmd_reconad_groups.addArgFlagString("-a", "attributes", "Comma-separated LDAP attributes, or -all", "-all");
cmd_reconad_groups.addArgFlagString("-n", "maxresults", "Max result count (0 = unlimited)", "0");
cmd_reconad_groups.addArgBool("-gc", "Search the Global Catalogue instead of LDAP");
cmd_reconad_groups.addArgFlagString("-s", "server", "Optional DC server:port for explicit binding", "-noserver");
cmd_reconad_groups.setPreHook(function (id, cmdline, parsed_json) { _reconad_hook("groups",    id, cmdline, parsed_json); });

var group_reconad = ax.create_commands_group("ReconAD-BOF", [cmd_reconad, cmd_reconad_users, cmd_reconad_computers, cmd_reconad_groups]);
ax.register_commands_group(group_reconad, ["beacon", "gopher", "kharon"], ["windows"], []);
