using System;
using System.Runtime.InteropServices;

namespace CallingApp
{
    public class CallingApp
    {
        [DllImport("EnclaveWrapper.dll")]
        public static extern IntPtr CreateObj(int x);

        [DllImport("EnclaveWrapper.dll")]
        public static extern void Call(IntPtr intPtr);

        [DllImport("EnclaveWrapper.dll")]
        public static extern int CallWallet(IntPtr intPtr, int index, string deviceId, string username, string password, string oldPassword);

        static void Main(string[] args)
        {

            //Call(intPtr);
            //new CallingApp().CallEnclaveWrapper("deviceId", "username", "password", "oldPassword");
            Console.WriteLine("Hello World!");
        }


        public int CallEnclaveWrapper(string deviceId, string username, string password, string oldPassword)
        {
            IntPtr intPtr = CreateObj(0);
            return CallWallet(intPtr, 1, deviceId, username, password, oldPassword);
        }
    }
}
