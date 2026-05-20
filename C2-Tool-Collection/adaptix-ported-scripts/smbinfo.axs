var metadata = {
    name: "Smbinfo",
    description: "Gather remote system version info via NetWkstaGetInfo"
};

var cmd_smbinfo = ax.create_command("smbinfo", "Gather remote system version info using the NetWkstaGetInfo API", "smbinfo <target>");
cmd_smbinfo.addArgString("target", true, "IP address or hostname of the remote system");
cmd_smbinfo.setPreHook(function (id, cmdline, parsed_json) {
    var target     = parsed_json["target"];
    var bof_params = ax.bof_pack("wstr", [target]);
    var bof_path   = ax.script_dir() + "Smbinfo." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, `Task: gather SMB info from ${target}`);
});

var group_smbinfo = ax.create_commands_group("Smbinfo-BOF", [cmd_smbinfo]);
ax.register_commands_group(group_smbinfo, ["beacon", "gopher", "kharon"], ["windows"], []);
