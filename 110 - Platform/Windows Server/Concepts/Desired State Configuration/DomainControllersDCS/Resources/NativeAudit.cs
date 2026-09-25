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

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U1)]
        private static extern bool AuditQuerySystemPolicy([In] Guid[] subcategories, uint count, out IntPtr policy);

        [DllImport("advapi32.dll")]
        private static extern void AuditFree(IntPtr buffer);

        public static uint Query(Guid subcategory)
        {
            IntPtr buffer = IntPtr.Zero;
            if (!AuditQuerySystemPolicy(new[] { subcategory }, 1, out buffer))
            {
                int error = Marshal.GetLastWin32Error();
                throw new Win32Exception(error, "AuditQuerySystemPolicy failed (Win32 " + error + "): " + new Win32Exception(error).Message);
            }
            try
            {
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
            }
        }
    }
}