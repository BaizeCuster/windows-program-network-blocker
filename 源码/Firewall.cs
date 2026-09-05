using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace AppNetworkBlocker
{
    public sealed class FirewallEntry
    {
        public string Path;
        public string Status;
    }

    public sealed class FirewallHealth
    {
        public bool Ready;
        public string Text;
    }

    public static class Firewall
    {
        public const string Group = "AppNetworkBlocker.7fa61582-17ca-43be-837c-d5c137df4211";
        private static dynamic Policy() { return Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2", true)); }

        public static string Normalize(string path)
        {
            return System.IO.Path.GetFullPath(Environment.ExpandEnvironmentVariables(path.Trim().Trim('"')));
        }

        public static string RuleName(string path, int direction)
        {
            using (SHA256 sha = SHA256.Create())
            {
                string hash = BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(Normalize(path).ToUpperInvariant()))).Replace("-", "");
                return "AppNetworkBlocker-" + hash + (direction == 1 ? "-IN" : "-OUT");
            }
        }

        public static FirewallHealth Health()
        {
            dynamic policy = Policy();
            int current = policy.CurrentProfileTypes;
            int modification = (int)policy.LocalPolicyModifyState;
            bool ready = modification == 0;
            List<string> parts = new List<string>();
            int[] profiles = { 1, 2, 4 };
            string[] names = { "域", "专用", "公用" };
            for (int i = 0; i < profiles.Length; i++)
            {
                bool enabled = policy.FirewallEnabled[profiles[i]];
                if (!enabled) ready = false;
                parts.Add(names[i] + (enabled ? "：已开启" : "：未开启") + ((current & profiles[i]) != 0 ? "（当前）" : ""));
            }
            if (modification != 0) parts.Add("本地规则可能被组策略限制，状态码 " + modification);
            return new FirewallHealth { Ready = ready, Text = String.Join("    ", parts) };
        }

        private static bool Valid(dynamic rule, string path, int direction)
        {
            return (string)rule.Grouping == Group &&
                String.Equals(Normalize((string)rule.ApplicationName), path, StringComparison.OrdinalIgnoreCase) &&
                (int)rule.Direction == direction && (int)rule.Action == 0 && (bool)rule.Enabled &&
                (int)rule.Protocol == 256 && ((int)rule.Profiles & 7) == 7 &&
                (string)rule.LocalAddresses == "*" && (string)rule.RemoteAddresses == "*" &&
                String.Equals((string)rule.InterfaceTypes, "All", StringComparison.OrdinalIgnoreCase) &&
                String.IsNullOrEmpty((string)rule.ServiceName);
        }

        public static List<FirewallEntry> List()
        {
            dynamic policy = Policy();
            Dictionary<string, int> states = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            foreach (dynamic rule in policy.Rules)
            {
                if ((string)rule.Grouping != Group || String.IsNullOrWhiteSpace((string)rule.ApplicationName)) continue;
                string path = Normalize((string)rule.ApplicationName);
                if (!states.ContainsKey(path)) states[path] = 0;
                int direction = (int)rule.Direction;
                if ((direction == 1 || direction == 2) && Valid(rule, path, direction)) states[path] |= direction;
            }
            return states.Select(x => new FirewallEntry {
                Path = x.Key,
                Status = x.Value == 3 ? "双向禁网规则已就绪" : "规则不完整 / 被修改"
            }).ToList();
        }

        public static void Block(string input)
        {
            string path = Normalize(input);
            if (!File.Exists(path) || !String.Equals(System.IO.Path.GetExtension(path), ".exe", StringComparison.OrdinalIgnoreCase))
                throw new IOException("请选择实际存在的 .exe 程序：" + path);
            dynamic policy = Policy();
            List<string> created = new List<string>();
            try
            {
                foreach (int direction in new int[] { 1, 2 })
                {
                    string name = RuleName(path, direction);
                    dynamic existing = null;
                    foreach (dynamic candidate in policy.Rules)
                    {
                        if (String.Equals((string)candidate.Name, name, StringComparison.OrdinalIgnoreCase)) { existing = candidate; break; }
                    }
                    if (existing != null)
                    {
                        if (!Valid(existing, path, direction)) throw new InvalidOperationException("同名规则已被修改，请先解除该程序的规则，再重新禁网。");
                        continue;
                    }
                    dynamic rule = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule", true));
                    rule.Name = name;
                    rule.Description = "程序断网工具：" + path + "；全部协议、地址、网络配置文件。";
                    rule.Grouping = Group;
                    rule.ApplicationName = path;
                    rule.Protocol = 256;
                    rule.LocalAddresses = "*";
                    rule.RemoteAddresses = "*";
                    rule.Direction = direction;
                    rule.Action = 0;
                    rule.Profiles = 7;
                    rule.InterfaceTypes = "All";
                    rule.EdgeTraversal = false;
                    rule.Enabled = true;
                    policy.Rules.Add(rule);
                    created.Add(name);
                    dynamic saved = policy.Rules.Item(name);
                    if (!Valid(saved, path, direction)) throw new InvalidOperationException("防火墙规则写入后校验失败。");
                }
            }
            catch (Exception original)
            {
                List<string> rollbackErrors = new List<string>();
                foreach (string name in created)
                {
                    try { policy.Rules.Remove(name); }
                    catch (Exception e) { rollbackErrors.Add(e.Message); }
                }
                if (rollbackErrors.Count > 0) throw new InvalidOperationException(original.Message + "；回滚未完成，请刷新后解除残留规则：" + String.Join("；", rollbackErrors));
                throw;
            }
        }

        public static void Unblock(string input)
        {
            string path = Normalize(input);
            dynamic policy = Policy();
            List<string> names = new List<string>();
            foreach (dynamic rule in policy.Rules)
            {
                if ((string)rule.Grouping == Group && !String.IsNullOrWhiteSpace((string)rule.ApplicationName) &&
                    String.Equals(Normalize((string)rule.ApplicationName), path, StringComparison.OrdinalIgnoreCase)) names.Add((string)rule.Name);
            }
            foreach (string name in names) policy.Rules.Remove(name);
            foreach (dynamic rule in policy.Rules)
                if ((string)rule.Grouping == Group && !String.IsNullOrWhiteSpace((string)rule.ApplicationName) &&
                    String.Equals(Normalize((string)rule.ApplicationName), path, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("规则仍存在，请刷新列表并检查管理员权限。");
        }
    }
}
