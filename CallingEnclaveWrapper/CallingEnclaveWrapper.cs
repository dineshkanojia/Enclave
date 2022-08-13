using System;
using System.Runtime.InteropServices;

namespace CallingEnclaveWrapper
{
    public class CallingEnclaveWrapper
    {
        [DllImport("EnclaveWrapper.dll")]
        public static extern IntPtr CreateObj(int x);

        [DllImport("EnclaveWrapper.dll")]
        public static extern void Call(IntPtr intPtr);

        [DllImport("EnclaveWrapper.dll")]
        public static extern int CallWallet(IntPtr intPtr, int index, string deviceId, string username, string password, string oldPassword);

        public int CallEnclaveWrapper(int command, string deviceId, string username, string password, string oldPassword)
        {
            IntPtr intPtr = CreateObj(0);
            return CallWallet(intPtr, command, deviceId, username, password, oldPassword);
        }
    }
}
