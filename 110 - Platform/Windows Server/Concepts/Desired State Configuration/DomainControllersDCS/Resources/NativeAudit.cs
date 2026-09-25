using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Blog.DC
{
    public static class NativeAudit
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct AuditPolicyInformation
        {
            public Guid Subcategory;
            public uint Flags;
            public Guid Category;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PrivilegeState
        {
            public uint Count;
            public uint LowPart;
            public int HighPart;
            public uint Attributes;
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U1)]
        private static extern bool AuditQuerySystemPolicy([In] Guid[] subcategories, uint count, out IntPtr policy);

        [DllImport("advapi32.dll")]
        private static extern void AuditFree(IntPtr buffer);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool LookupPrivilegeValue(string system, string name, out long identifier);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool AdjustTokenPrivileges(IntPtr token, [MarshalAs(UnmanagedType.Bool)] bool disableAll, ref PrivilegeState state, uint length, out PrivilegeState previous, out uint required);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr handle);

        private static Win32Exception Failure(string operation, int error)
        {
            return new Win32Exception(error, operation + " failed (Win32 " + error + "): " + new Win32Exception(error).Message);
        }

        public static uint Query(Guid subcategory)
        {
            IntPtr buffer = IntPtr.Zero;
            IntPtr token = IntPtr.Zero;
            PrivilegeState previous = new PrivilegeState();
            bool restorePrivilege = false;
            try
            {
                if (!AuditQuerySystemPolicy(new[] { subcategory }, 1, out buffer))
                {
                    int queryError = Marshal.GetLastWin32Error();
                    if (queryError != 5 && queryError != 1314) throw Failure("AuditQuerySystemPolicy", queryError);
                    if (!OpenProcessToken(GetCurrentProcess(), 0x0028, out token)) throw Failure("OpenProcessToken", Marshal.GetLastWin32Error());
                    long identifier;
                    if (!LookupPrivilegeValue(null, "SeSecurityPrivilege", out identifier)) throw Failure("LookupPrivilegeValue", Marshal.GetLastWin32Error());
                    PrivilegeState enabled = new PrivilegeState
                    {
                        Count = 1,
                        LowPart = unchecked((uint)identifier),
                        HighPart = (int)(identifier >> 32),
                        Attributes = 2
                    };
                    uint required;
                    if (!AdjustTokenPrivileges(token, false, ref enabled, (uint)Marshal.SizeOf(typeof(PrivilegeState)), out previous, out required))
                        throw Failure("AdjustTokenPrivileges", Marshal.GetLastWin32Error());
                    int adjustmentError = Marshal.GetLastWin32Error();
                    restorePrivilege = previous.Count != 0;
                    if (adjustmentError != 0) throw Failure("Enabling the existing SeSecurityPrivilege", adjustmentError);
                    if (!AuditQuerySystemPolicy(new[] { subcategory }, 1, out buffer)) throw Failure("AuditQuerySystemPolicy", Marshal.GetLastWin32Error());
                }
                if (buffer == IntPtr.Zero) throw new InvalidOperationException("AuditQuerySystemPolicy returned no policy data.");
                AuditPolicyInformation policy = (AuditPolicyInformation)Marshal.PtrToStructure(buffer, typeof(AuditPolicyInformation));
                if (policy.Subcategory != subcategory)
                {
                    throw new InvalidOperationException("AuditQuerySystemPolicy returned another subcategory.");
                }
                return policy.Flags;
            }
            finally
            {
                if (buffer != IntPtr.Zero) AuditFree(buffer);
                if (token != IntPtr.Zero)
                {
                    if (restorePrivilege)
                    {
                        PrivilegeState ignored;
                        uint required;
                        AdjustTokenPrivileges(token, false, ref previous, (uint)Marshal.SizeOf(typeof(PrivilegeState)), out ignored, out required);
                    }
                    CloseHandle(token);
                }
            }
        }
    }
}