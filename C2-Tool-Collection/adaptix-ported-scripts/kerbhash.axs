var metadata = {
    name: "KerbHash",
    description: "Hash passwords to Kerberos keys (rc4_hmac, aes128, aes256, des_cbc_md5)"
};

var cmd_kerbhash = ax.create_command("kerbhash", "Hash a password to Kerberos keys (rc4_hmac, aes128_cts_hmac_sha1, aes256_cts_hmac_sha1, des_cbc_md5)", "kerbhash <password> <username> <domain.fqdn>");
cmd_kerbhash.addArgString("password", true, "Plaintext password to hash");
cmd_kerbhash.addArgString("username", true, "Username (used as AES key salt)");
cmd_kerbhash.addArgString("domain",   true, "Domain FQDN (used as AES key salt)");
cmd_kerbhash.setPreHook(function (id, cmdline, parsed_json) {
    var password   = parsed_json["password"];
    var username   = parsed_json["username"];
    var domain     = parsed_json["domain"];
    var bof_params = ax.bof_pack("wstr,wstr,wstr", [password, username, domain]);
    var bof_path   = ax.script_dir() + "KerbHash." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "Task: KerbHash BOF by Outflank");
});

var group_kerbhash = ax.create_commands_group("KerbHash-BOF", [cmd_kerbhash]);
ax.register_commands_group(group_kerbhash, ["beacon", "gopher", "kharon"], ["windows"], []);
