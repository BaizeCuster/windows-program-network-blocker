using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace AppNetworkBlocker
{
    // x64 layouts verified against the installed Windows SDK fwpmtypes.h.
    // Filters are scoped to one exact ALE application ID, never to the proxy process.
    public static class StrongFirewall
    {
        private static readonly Guid ProviderKey = new Guid("69ba60cd-239b-4cdb-89a4-cebe927a688a");
        private static readonly Guid SublayerKey = new Guid("496563fc-7f1f-4a25-880e-3666bd78ebf4");
        private static readonly Guid AppIdKey = new Guid("d78e1e87-8644-4ea5-9437-d809ecefc971");
        private static readonly Guid[] Layers = {
            new Guid("c38d57d1-05a7-4c33-904f-7fbceee60e82"),
            new Guid("4a72393b-319f-44bc-84c3-ba54dcb3b6b4"),
            new Guid("e1cd9fe7-f4b5-4273-96c0-592e487b8650"),
            new Guid("a3b42c97-9f04-4672-b87e-cee9c483257f")
        };
        private const uint NotFound = 0x80320003;
        private const uint Exists = 0x80320009;

        [StructLayout(LayoutKind.Sequential)] private struct Blob { public uint Size; public IntPtr Data; }
        [StructLayout(LayoutKind.Sequential)] private struct Display { public IntPtr Name; public IntPtr Description; }
        [StructLayout(LayoutKind.Explicit, Size = 16)] private struct Value
        {
            [FieldOffset(0)] public uint Type;
            [FieldOffset(8)] public IntPtr Pointer;
            [FieldOffset(8)] public byte Byte;
        }
        [StructLayout(LayoutKind.Explicit, Size = 200)] private struct Filter
        {
            [FieldOffset(0)] public Guid Key;
            [FieldOffset(16)] public Display Display;
            [FieldOffset(32)] public uint Flags;
            [FieldOffset(40)] public IntPtr Provider;
            [FieldOffset(48)] public Blob Data;
            [FieldOffset(64)] public Guid Layer;
            [FieldOffset(80)] public Guid Sublayer;
            [FieldOffset(96)] public Value Weight;
            [FieldOffset(112)] public uint Count;
            [FieldOffset(120)] public IntPtr Conditions;
            [FieldOffset(128)] public uint Action;
            [FieldOffset(176)] public ulong Id;
        }
        [StructLayout(LayoutKind.Sequential)] private struct Provider
        {
            public Guid Key; public Display Display; public uint Flags; public Blob Data; public IntPtr Service;
        }
        [StructLayout(LayoutKind.Sequential)] private struct Sublayer
        {
            public Guid Key; public Display Display; public uint Flags; public IntPtr Provider; public Blob Data; public ushort Weight;
        }
        [StructLayout(LayoutKind.Sequential)] private struct Condition
        {
            public Guid Key; public uint Match; public Value Value;
        }

        [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)] private static extern uint FwpmEngineOpen0(string server, uint authentication, IntPtr identity, IntPtr session, out IntPtr engine);
        [DllImport("fwpuclnt.dll")] private static extern uint FwpmEngineClose0(IntPtr engine);
        [DllImport("fwpuclnt.dll")] private static extern uint FwpmTransactionBegin0(IntPtr engine, uint flags);
        [DllImport("fwpuclnt.dll")] private static extern uint FwpmTransactionCommit0(IntPtr engine);
        [DllImport("fwpuclnt.dll")] private static extern uint FwpmTransactionAbort0(IntPtr engine);
        [DllImport("fwpuclnt.dll")] private static extern uint FwpmProviderAdd0(IntPtr engine, ref Provider provider, IntPtr security);
        [DllImport("fwpuclnt.dll")] private static extern uint FwpmSubLayerAdd0(IntPtr engine, ref Sublayer sublayer, IntPtr security);
        [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)] private static extern uint FwpmGetAppIdFromFileName0(string path, out IntPtr blob);
        [DllImport("fwpuclnt.dll")] private static extern uint FwpmFilterAdd0(IntPtr engine, ref Filter filter, IntPtr security, out ulong id);
        [DllImport("fwpuclnt.dll")] private static extern uint FwpmFilterGetByKey0(IntPtr engine, ref Guid key, out IntPtr filter);
        [DllImport("fwpuclnt.dll")] private static extern uint FwpmFilterDeleteByKey0(IntPtr engine, ref Guid key);
        [DllImport("fwpuclnt.dll")] private static extern uint FwpmFilterCreateEnumHandle0(IntPtr engine, IntPtr template, out IntPtr enumeration);
        [DllImport("fwpuclnt.dll")] private static extern uint FwpmFilterEnum0(IntPtr engine, IntPtr enumeration, uint requested, out IntPtr entries, out uint returned);
        [DllImport("fwpuclnt.dll")] private static extern uint FwpmFilterDestroyEnumHandle0(IntPtr engine, IntPtr enumeration);
        [DllImport("fwpuclnt.dll")] private static extern void FwpmFreeMemory0(ref IntPtr memory);

        private sealed class Memory : IDisposable
        {
            private readonly List<IntPtr> allocations = new List<IntPtr>();
            public IntPtr Text(string value) { IntPtr p = Marshal.StringToHGlobalUni(value); allocations.Add(p); return p; }
            public IntPtr Structure<T>(T value) where T : struct
            {
                IntPtr p = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(T)));
                allocations.Add(p); Marshal.StructureToPtr(value, p, false); return p;
            }
            public void Dispose() { foreach (IntPtr p in allocations) Marshal.FreeHGlobal(p); }
        }
        private sealed class Engine : IDisposable
        {
            public IntPtr Handle;
            public Engine()
            {
                if (IntPtr.Size != 8) throw new PlatformNotSupportedException("加强禁网需要 64 位 Windows。");
                Check(FwpmEngineOpen0(null, 10, IntPtr.Zero, IntPtr.Zero, out Handle), "打开 Windows 网络过滤引擎");
            }
            public void Dispose() { if (Handle != IntPtr.Zero) { FwpmEngineClose0(Handle); Handle = IntPtr.Zero; } }
        }
        private static void Check(uint code, string operation)
        {
            if (code != 0) throw new InvalidOperationException(operation + "失败（0x" + code.ToString("X8") + "）：" + new Win32Exception(unchecked((int)code)).Message);
        }
        private static Guid Key(string path, int index)
        {
            using (SHA256 sha = SHA256.Create())
            {
                byte[] digest = sha.ComputeHash(Encoding.UTF8.GetBytes("AppNetworkBlocker.WFP.v1|" + Firewall.Normalize(path).ToUpperInvariant() + "|" + index));
                byte[] bytes = new byte[16]; Array.Copy(digest, bytes, 16); return new Guid(bytes);
            }
        }
        private static bool Owned(Filter filter)
        {
            return filter.Provider != IntPtr.Zero && (Guid)Marshal.PtrToStructure(filter.Provider, typeof(Guid)) == ProviderKey && filter.Sublayer == SublayerKey;
        }
        private static bool Valid(Filter filter, int index)
        {
            if (!Owned(filter) || filter.Layer != Layers[index] || filter.Action != 0x1001 || (filter.Flags & 1) == 0 || (filter.Flags & 0x20) != 0 || filter.Count != 1 || filter.Conditions == IntPtr.Zero) return false;
            Condition condition = (Condition)Marshal.PtrToStructure(filter.Conditions, typeof(Condition));
            return condition.Key == AppIdKey && condition.Match == 0 && condition.Value.Type == 12 && condition.Value.Pointer != IntPtr.Zero;
        }
        private static string SavedPath(Filter filter)
        {
            if (filter.Data.Data == IntPtr.Zero || filter.Data.Size < 4 || filter.Data.Size > 65536 || filter.Data.Size % 2 != 0) return null;
            return Marshal.PtrToStringUni(filter.Data.Data, (int)filter.Data.Size / 2).TrimEnd('\0');
        }
        public static Dictionary<string, int> List()
        {
            Dictionary<string, int> paths = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            using (Engine engine = new Engine())
            {
                IntPtr enumeration;
                Check(FwpmFilterCreateEnumHandle0(engine.Handle, IntPtr.Zero, out enumeration), "读取加强规则");
                try
                {
                    while (true)
                    {
                        IntPtr entries = IntPtr.Zero; uint returned;
                        Check(FwpmFilterEnum0(engine.Handle, enumeration, 256, out entries, out returned), "枚举加强规则");
                        try
                        {
                            for (int i = 0; i < returned; i++)
                            {
                                Filter filter = (Filter)Marshal.PtrToStructure(Marshal.ReadIntPtr(entries, i * IntPtr.Size), typeof(Filter));
                                if (!Owned(filter)) continue;
                                string path = SavedPath(filter);
                                if (String.IsNullOrWhiteSpace(path)) continue;
                                if (!paths.ContainsKey(path)) paths[path] = 0;
                                for (int n = 0; n < Layers.Length; n++) if (Valid(filter, n) && filter.Key == Key(path, n)) paths[path] |= 1 << n;
                            }
                        }
                        finally { if (entries != IntPtr.Zero) FwpmFreeMemory0(ref entries); }
                        if (returned < 256) break;
                    }
                }
                finally { FwpmFilterDestroyEnumHandle0(engine.Handle, enumeration); }
            }
            return paths;
        }
        public static void Block(string input)
        {
            string path = Firewall.Normalize(input);
            if (!File.Exists(path) || !String.Equals(Path.GetExtension(path), ".exe", StringComparison.OrdinalIgnoreCase)) throw new IOException("请选择实际存在的 EXE：" + path);
            using (Engine engine = new Engine())
            using (Memory memory = new Memory())
            {
                IntPtr appId = IntPtr.Zero;
                Check(FwpmGetAppIdFromFileName0(path, out appId), "读取程序身份");
                bool transaction = false;
                try
                {
                    Check(FwpmTransactionBegin0(engine.Handle, 0), "开始规则事务"); transaction = true;
                    IntPtr providerPointer = memory.Structure(ProviderKey);
                    Display display = new Display { Name = memory.Text("AppNetworkBlocker Strong Isolation"), Description = memory.Text("Per executable network isolation, including loopback. Restore with AppNetworkBlocker v2.") };
                    Provider provider = new Provider { Key = ProviderKey, Display = display, Flags = 1 };
                    uint added = FwpmProviderAdd0(engine.Handle, ref provider, IntPtr.Zero);
                    if (added != Exists) Check(added, "注册加强规则提供者");
                    Sublayer sublayer = new Sublayer { Key = SublayerKey, Display = display, Flags = 1, Provider = providerPointer, Weight = 65535 };
                    added = FwpmSubLayerAdd0(engine.Handle, ref sublayer, IntPtr.Zero);
                    if (added != Exists) Check(added, "注册加强过滤层");
                    Condition condition = new Condition { Key = AppIdKey, Match = 0, Value = new Value { Type = 12, Pointer = appId } };
                    IntPtr conditionPointer = memory.Structure(condition);
                    for (int i = 0; i < Layers.Length; i++)
                    {
                        Guid key = Key(path, i);
                        DeleteOwned(engine.Handle, key);
                        Filter filter = new Filter {
                            Key = key, Display = new Display { Name = memory.Text("AppNetworkBlocker Strong " + Path.GetFileName(path) + " [" + i + "]"), Description = memory.Text(path) },
                            Flags = 1, Provider = providerPointer,
                            Data = new Blob { Size = (uint)((path.Length + 1) * 2), Data = memory.Text(path) },
                            Layer = Layers[i], Sublayer = SublayerKey, Weight = new Value { Type = 1, Byte = 15 },
                            Count = 1, Conditions = conditionPointer, Action = 0x1001
                        };
                        ulong id;
                        Check(FwpmFilterAdd0(engine.Handle, ref filter, IntPtr.Zero, out id), "写入加强禁网规则");
                        IntPtr saved;
                        Check(FwpmFilterGetByKey0(engine.Handle, ref key, out saved), "校验加强规则");
                        try
                        {
                            Filter readback = (Filter)Marshal.PtrToStructure(saved, typeof(Filter));
                            if (!Valid(readback, i)) throw new InvalidOperationException("加强规则读回校验失败。");
                        }
                        finally { FwpmFreeMemory0(ref saved); }
                    }
                    Check(FwpmTransactionCommit0(engine.Handle), "保存加强规则事务"); transaction = false;
                }
                finally
                {
                    if (transaction) FwpmTransactionAbort0(engine.Handle);
                    if (appId != IntPtr.Zero) FwpmFreeMemory0(ref appId);
                }
            }
        }
        private static void DeleteOwned(IntPtr engine, Guid key)
        {
            IntPtr existing;
            uint code = FwpmFilterGetByKey0(engine, ref key, out existing);
            if (code == NotFound) return;
            Check(code, "读取已有加强规则");
            try { if (!Owned((Filter)Marshal.PtrToStructure(existing, typeof(Filter)))) throw new InvalidOperationException("规则标识与其他工具冲突，未覆盖其他工具规则。"); }
            finally { FwpmFreeMemory0(ref existing); }
            Check(FwpmFilterDeleteByKey0(engine, ref key), "移除已有加强规则");
        }
        public static void Unblock(string input)
        {
            string path = Firewall.Normalize(input);
            using (Engine engine = new Engine())
            {
                Check(FwpmTransactionBegin0(engine.Handle, 0), "开始解除规则事务");
                bool committed = false;
                try
                {
                    for (int i = 0; i < Layers.Length; i++) DeleteOwned(engine.Handle, Key(path, i));
                    Check(FwpmTransactionCommit0(engine.Handle), "保存解除规则事务"); committed = true;
                }
                finally { if (!committed) FwpmTransactionAbort0(engine.Handle); }
            }
        }
    }
}
