var metadata = {
    name: "Outflank-C2TC",
    description: "Outflank C2-Tool-Collection — all tools in one load",
    nosave: true
};

var path = ax.script_dir();
ax.script_load(path + "askcreds.axs");
ax.script_load(path + "machineaccounts.axs");
ax.script_load(path + "cve-2022-26923.axs");
ax.script_load(path + "domaininfo.axs");
ax.script_load(path + "findobjects.axs");
ax.script_load(path + "kerberoast.axs");
ax.script_load(path + "kerbhash.axs");
ax.script_load(path + "klist.axs");
ax.script_load(path + "lapsdump.axs");
ax.script_load(path + "petitpotam.axs");
ax.script_load(path + "petitpotam_rdll.axs");
ax.script_load(path + "psc.axs");
ax.script_load(path + "psw.axs");
ax.script_load(path + "psk.axs");
ax.script_load(path + "psm.axs");
ax.script_load(path + "psx.axs");
ax.script_load(path + "reconad.axs");
ax.script_load(path + "remotepipelist.axs");
ax.script_load(path + "smbinfo.axs");
ax.script_load(path + "sprayad.axs");
ax.script_load(path + "startwebclient.axs");
ax.script_load(path + "wdtoggle.axs");
ax.script_load(path + "winver.axs");
ax.script_load(path + "adpeas.axs");
