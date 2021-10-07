using System;
using System.Runtime.InteropServices;
using EasyHook;
using System.Threading;
using System.Windows.Forms;
using System.Diagnostics;
using System.Collections.Generic;

namespace ClassLibrary1
{
    [Serializable]
    public class HookParameter
    {
        public string Msg { get; set; }
        public int HostProcessId { get; set; }
    }

    public class Main : IEntryPoint
    {
        private static List<string> logs = new List<string>();

        public Main(
            RemoteHooking.IContext context,
            string channelName
            , HookParameter parameter
            )
        {
            //MessageBox.Show(parameter.Msg, "Hooked");
            Debug.WriteLine(parameter.Msg);
        }

        public void Run(
            RemoteHooking.IContext context,
            string channelName
            , HookParameter parameter
            )
        {
            try
            {
                var createFileHook = LocalHook.Create(
                    LocalHook.GetProcAddress("kernel32.dll", "CreateFileW"),
                    new DCreateFile(CreateFile_Hooked),
                    null);
                createFileHook.ThreadACL.SetExclusiveACL(new int[1]);

                var reOpenFileHook = LocalHook.Create(
                    LocalHook.GetProcAddress("kernel32.dll", "ReOpenFile"),
                    new DReOpenFile(ReOpenFile_Hooked),
                    null);
                reOpenFileHook.ThreadACL.SetExclusiveACL(new int[1]);

                var deleteFileHook = LocalHook.Create(
                    LocalHook.GetProcAddress("kernel32.dll", "DeleteFileW"),
                    new DDeleteFile(DeleteFile_Hooked),
                    null);
                deleteFileHook.ThreadACL.SetExclusiveACL(new int[1]);

                var readFileHook = LocalHook.Create(
                    LocalHook.GetProcAddress("kernel32.dll", "ReadFile"),
                    new DReadFile(ReadFile_Hooked),
                    null);
                readFileHook.ThreadACL.SetExclusiveACL(new int[1]);

                var writeFileHook = LocalHook.Create(
                    LocalHook.GetProcAddress("kernel32.dll", "WriteFile"),
                    new DWriteFile(WriteFile_Hooked),
                    null);
                writeFileHook.ThreadACL.SetExclusiveACL(new int[1]);


                var regCreateKeyExHook = LocalHook.Create(
                    LocalHook.GetProcAddress("advapi32.dll", "RegCreateKeyExW"),
                    new DRegCreateKeyEx(RegCreateKeyEx_Hooked),
                    null);
                regCreateKeyExHook.ThreadACL.SetExclusiveACL(new int[1]);

                var regOpenKeyExHook = LocalHook.Create(
                    LocalHook.GetProcAddress("advapi32.dll", "RegOpenKeyExW"),
                    new DRegOpenKeyEx(RegOpenKeyEx_Hooked),
                    null);
                regOpenKeyExHook.ThreadACL.SetExclusiveACL(new int[1]);

                var regSetValueExHook = LocalHook.Create(
                    LocalHook.GetProcAddress("advapi32.dll", "RegSetValueExW"),
                    new DRegSetValueEx(RegSetValueEx_Hooked),
                    null);
                regSetValueExHook.ThreadACL.SetExclusiveACL(new int[1]);

                var regGetValueHook = LocalHook.Create(
                    LocalHook.GetProcAddress("advapi32.dll", "RegGetValueW"),
                    new DRegGetValue(RegGetValue_Hooked),
                    null);
                regGetValueHook.ThreadACL.SetExclusiveACL(new int[1]);
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
                return;
            }

            try
            {
                while (true)
                {
                    Thread.Sleep(10);
                }
            }
            catch
            {

            }
        }

        #region 文件相关

        [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode)]
        public static extern IntPtr CreateFile(string fileName, uint desiredAccess, uint shareMode, IntPtr securityAttributes, uint creationDisposition, uint flagsAndAttributes, IntPtr hTemplateFile);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        delegate IntPtr DCreateFile(string fileName, uint desiredAccess, uint shareMode, IntPtr securityAttributes, uint creationDisposition, uint flagsAndAttributes, IntPtr hTemplateFile);

        static IntPtr CreateFile_Hooked(string fileName, uint desiredAccess, uint shareMode, IntPtr securityAttributes, uint creationDisposition, uint flagsAndAttributes, IntPtr hTemplateFile)
        {
            //logs.Add("CreateFile_Hooked " + fileName);
            Debug.WriteLine("CreateFile_Hooked " + fileName);
            return CreateFile(fileName, desiredAccess, shareMode, securityAttributes, creationDisposition, flagsAndAttributes, hTemplateFile);
        }

        [DllImport("kernel32.dll", EntryPoint = "ReOpenFile")]
        public static extern IntPtr ReOpenFile(IntPtr hOriginalFile, uint desiredAccess, uint shareMode, uint flagsAndAttributes);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate IntPtr DReOpenFile(IntPtr hOriginalFile, uint desiredAccess, uint shareMode, uint flagsAndAttributes);

        static IntPtr ReOpenFile_Hooked(IntPtr hOriginalFile, uint desiredAccess, uint shareMode, uint flagsAndAttributes)
        {
            return ReOpenFile(hOriginalFile, desiredAccess, shareMode, flagsAndAttributes);
        }

        [DllImport("kernel32.dll", EntryPoint = "DeleteFileW", CharSet = CharSet.Unicode)]
        public static extern bool DeleteFile(string fileName);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        delegate bool DDeleteFile(string fileName);

        static bool DeleteFile_Hooked(string fileName)
        {
            //logs.Add("CreateFile_Hooked " + fileName);
            Debug.WriteLine("DeleteFile_Hooked " + fileName);
            return DeleteFile(fileName);
        }

        [DllImport("kernel32.dll", EntryPoint = "ReadFile")]
        public static extern bool ReadFile(IntPtr hFile, IntPtr buffer, uint numberOfBytesToRead, IntPtr numberOfBytesRead, IntPtr overlapped);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate bool DReadFile(IntPtr hFile, IntPtr buffer, uint numberOfBytesToRead, IntPtr numberOfBytesRead, IntPtr overlapped);

        static bool ReadFile_Hooked(IntPtr hFile, IntPtr buffer, uint numberOfBytesToRead, IntPtr numberOfBytesRead, IntPtr overlapped)
        {
            return ReadFile(hFile, buffer, numberOfBytesToRead, numberOfBytesRead, overlapped);
        }

        [DllImport("kernel32.dll", EntryPoint = "WriteFile")]
        public static extern bool WriteFile(IntPtr hFile, IntPtr buffer, uint numberOfBytesToWrite, IntPtr numberOfBytesWritten, IntPtr overlapped);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate bool DWriteFile(IntPtr hFile, IntPtr buffer, uint numberOfBytesToWrite, IntPtr numberOfBytesWritten, IntPtr overlapped);

        static bool WriteFile_Hooked(IntPtr hFile, IntPtr buffer, uint numberOfBytesToWrite, IntPtr numberOfBytesWritten, IntPtr overlapped)
        {
            return WriteFile(hFile, buffer, numberOfBytesToWrite, numberOfBytesWritten, overlapped);
        }

        #endregion

        #region 注册表
        [DllImport("advapi32.dll", EntryPoint = "RegCreateKeyExW", CharSet = CharSet.Unicode)]
        public static extern long RegCreateKeyEx(IntPtr hKey, string subKey, uint reserved, IntPtr @class, uint options, uint desired, IntPtr securityAttributes, IntPtr result, IntPtr disposition);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        delegate long DRegCreateKeyEx(IntPtr hKey, string subKey, uint reserved, IntPtr @class, uint options, uint desired, IntPtr securityAttributes, IntPtr result, IntPtr disposition);

        static long RegCreateKeyEx_Hooked(IntPtr hKey, string subKey, uint reserved, IntPtr @class, uint options, uint desired, IntPtr securityAttributes, IntPtr result, IntPtr disposition)
        {
            logs.Add("RegCreateKeyEx_Hooked " + subKey);
            return RegCreateKeyEx(hKey, subKey, reserved, @class, options, desired, securityAttributes, result, disposition);
        }

        [DllImport("advapi32.dll", EntryPoint = "RegOpenKeyExW", CharSet = CharSet.Unicode)]
        public static extern long RegOpenKeyEx(IntPtr hKey, string subKey, uint options, uint desired, IntPtr result);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        delegate long DRegOpenKeyEx(IntPtr hKey, string subKey, uint options, uint desired, IntPtr result);

        static long RegOpenKeyEx_Hooked(IntPtr hKey, string subKey, uint options, uint desired, IntPtr result)
        {
            logs.Add("RegOpenKeyEx_Hooked " + subKey);
            return RegOpenKeyEx(hKey, subKey, options, desired, result);
        }

        [DllImport("advapi32.dll", EntryPoint = "RegSetValueExW", CharSet = CharSet.Unicode)]
        public static extern long RegSetValueEx(IntPtr hKey, string valueName, uint reserved, uint type, IntPtr byteData, uint data);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        delegate long DRegSetValueEx(IntPtr hKey, string valueName, uint reserved, uint type, IntPtr byteData, uint data);

        static long RegSetValueEx_Hooked(IntPtr hKey, string valueName, uint reserved, uint type, IntPtr byteData, uint data)
        {
            logs.Add("RegSetValueEx_Hooked " + valueName);
            return RegSetValueEx(hKey, valueName, reserved, type, byteData, data);
        }

        [DllImport("advapi32.dll", EntryPoint = "RegGetValueW", CharSet = CharSet.Unicode)]
        public static extern long RegGetValue(IntPtr hKey, string subKey, string value, uint flags, IntPtr type, IntPtr voidData, IntPtr data);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        delegate long DRegGetValue(IntPtr hKey, string subKey, string value, uint flags, IntPtr type, IntPtr voidData, IntPtr data);

        static long RegGetValue_Hooked(IntPtr hKey, string subKey, string value, uint flags, IntPtr type, IntPtr voidData, IntPtr data)
        {
            logs.Add("RegGetValue_Hooked " + subKey + " " + value);
            return RegGetValue(hKey, subKey, value, flags, type, voidData, data);
        }
        #endregion
    }
}
