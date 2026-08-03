using System.Runtime.InteropServices;

namespace PrivescCheckExe.Core;

public sealed class SvcInfo
{
    public string Name = "";
    public string DisplayName = "";
    public string BinaryPath = "";
    public string State = "";
    public uint ServiceType;
}

/// <summary>
/// Native SCM enumeration - replaces WMI Win32_Service (System.Management is not
/// AOT/trim-friendly). Enumerates Win32 services and reads each binary path via
/// QueryServiceConfig.
/// </summary>
public static class NativeServices
{
    private const int SC_MANAGER_ENUMERATE_SERVICE = 0x0004;
    private const int SC_STATUS_PROCESS_INFO = 0;
    private const int SERVICE_WIN32 = 0x00000030;
    private const int SERVICE_STATE_ALL = 0x0003;
    private const uint SERVICE_QUERY_CONFIG = 0x0001;

    [StructLayout(LayoutKind.Sequential)]
    private struct ENUM_SERVICE_STATUS_PROCESS
    {
        public IntPtr lpServiceName;
        public IntPtr lpDisplayName;
        public SERVICE_STATUS_PROCESS ServiceStatusProcess;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SERVICE_STATUS_PROCESS
    {
        public uint dwServiceType;
        public uint dwCurrentState;
        public uint dwControlsAccepted;
        public uint dwWin32ExitCode;
        public uint dwServiceSpecificExitCode;
        public uint dwCheckPoint;
        public uint dwWaitHint;
        public uint dwProcessId;
        public uint dwServiceFlags;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct QUERY_SERVICE_CONFIG
    {
        public uint dwServiceType;
        public uint dwStartType;
        public uint dwErrorControl;
        public IntPtr lpBinaryPathName;
        public IntPtr lpLoadOrderGroup;
        public uint dwTagId;
        public IntPtr lpDependencies;
        public IntPtr lpServiceStartName;
        public IntPtr lpDisplayName;
    }

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenSCManager(string? machine, string? db, uint access);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool EnumServicesStatusEx(IntPtr hSC, int infoLevel, int serviceType,
        int serviceState, IntPtr lpServices, uint cbBufSize, out uint pcbBytesNeeded,
        out uint lpServicesReturned, ref uint lpResumeHandle, string? groupName);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenService(IntPtr hSC, string name, uint access);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool QueryServiceConfig(IntPtr hSvc, IntPtr lpConfig, uint cbBufSize, out uint pcbBytesNeeded);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CloseServiceHandle(IntPtr h);

    public static List<SvcInfo> EnumerateWin32Services()
    {
        var list = new List<SvcInfo>();
        IntPtr sc = OpenSCManager(null, null, SC_MANAGER_ENUMERATE_SERVICE);
        if (sc == IntPtr.Zero) return list;
        try
        {
            uint resume = 0;
            EnumServicesStatusEx(sc, SC_STATUS_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                IntPtr.Zero, 0, out uint needed, out _, ref resume, null);
            if (needed == 0) return list;

            IntPtr buf = Marshal.AllocHGlobal((int)needed);
            try
            {
                resume = 0;
                if (!EnumServicesStatusEx(sc, SC_STATUS_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                    buf, needed, out _, out uint returned, ref resume, null))
                {
                    return list;
                }
                int size = Marshal.SizeOf<ENUM_SERVICE_STATUS_PROCESS>();
                for (int i = 0; i < returned; i++)
                {
                    IntPtr cur = buf + (i * size);
                    var ess = Marshal.PtrToStructure<ENUM_SERVICE_STATUS_PROCESS>(cur);
                    string name = Marshal.PtrToStringUni(ess.lpServiceName) ?? "";
                    string disp = Marshal.PtrToStringUni(ess.lpDisplayName) ?? "";
                    list.Add(new SvcInfo
                    {
                        Name = name,
                        DisplayName = disp,
                        State = StateName(ess.ServiceStatusProcess.dwCurrentState),
                        BinaryPath = QueryBinaryPath(sc, name),
                        ServiceType = ess.ServiceStatusProcess.dwServiceType
                    });
                }
            }
            finally { Marshal.FreeHGlobal(buf); }
        }
        finally { CloseServiceHandle(sc); }
        return list;
    }

    private static string StateName(uint s) => s switch
    {
        1 => "Stopped", 2 => "Start Pending", 3 => "Stop Pending",
        4 => "Running", 5 => "Continue Pending", 6 => "Pause Pending",
        7 => "Paused", _ => "Unknown"
    };

    private static string QueryBinaryPath(IntPtr sc, string name)
    {
        IntPtr svc = OpenService(sc, name, SERVICE_QUERY_CONFIG);
        if (svc == IntPtr.Zero) return "";
        try
        {
            QueryServiceConfig(svc, IntPtr.Zero, 0, out uint needed);
            if (needed == 0) return "";
            IntPtr buf = Marshal.AllocHGlobal((int)needed);
            try
            {
                if (!QueryServiceConfig(svc, buf, needed, out _)) return "";
                var cfg = Marshal.PtrToStructure<QUERY_SERVICE_CONFIG>(buf);
                return Marshal.PtrToStringUni(cfg.lpBinaryPathName) ?? "";
            }
            finally { Marshal.FreeHGlobal(buf); }
        }
        finally { CloseServiceHandle(svc); }
    }
}