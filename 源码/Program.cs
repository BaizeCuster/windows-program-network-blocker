using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace AppNetworkBlocker
{
    internal static class Program
    {
        [STAThread]
        private static void Main(string[] args)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            if (args.Length == 2 && args[0] == "--preview")
            {
                using (MainForm form = new MainForm(true))
                {
                    form.Show();
                    Application.DoEvents();
                    using (Bitmap bitmap = new Bitmap(form.Width, form.Height))
                    {
                        form.DrawToBitmap(bitmap, new Rectangle(Point.Empty, form.Size));
                        bitmap.Save(args[1], System.Drawing.Imaging.ImageFormat.Png);
                    }
                }
                return;
            }
            bool admin = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
            if (!admin)
            {
                MessageBox.Show("请右键本工具，选择“以管理员身份运行”。写入防火墙规则需要管理员权限。", "需要管理员权限", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            Application.Run(new MainForm(false));
        }
    }

    public sealed class MainForm : Form
    {
        private readonly DataGridView grid = new DataGridView();
        private readonly Label healthLabel = new Label();
        private readonly Label resultLabel = new Label();
        private readonly List<Button> buttons = new List<Button>();
        private readonly bool preview;
        private bool busy;
        private bool ready;
        private readonly Color ink = Color.FromArgb(29, 42, 62);
        private readonly Color blue = Color.FromArgb(35, 91, 212);

        public MainForm(bool isPreview)
        {
            preview = isPreview;
            Text = "程序断网工具 v2 · 加强禁网";
            ClientSize = new Size(1060, 710);
            MinimumSize = new Size(960, 660);
            StartPosition = FormStartPosition.CenterScreen;
            Font = new Font("Microsoft YaHei UI", 10F);
            BackColor = Color.FromArgb(244, 247, 252);
            ForeColor = ink;
            AutoScaleMode = AutoScaleMode.Dpi;

            TableLayoutPanel layout = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(26, 22, 26, 18), ColumnCount = 1, RowCount = 7 };
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            foreach (int height in new int[] { 78, 57, 55 }) layout.RowStyles.Add(new RowStyle(SizeType.Absolute, height));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            foreach (int height in new int[] { 58, 62, 40 }) layout.RowStyles.Add(new RowStyle(SizeType.Absolute, height));
            Controls.Add(layout);

            Panel heading = new Panel { Dock = DockStyle.Fill };
            heading.Controls.Add(new Label { Text = "让本地软件，保持离线。", Font = new Font(Font.FontFamily, 23F, FontStyle.Bold), AutoSize = true, Location = new Point(0, 0) });
            heading.Controls.Add(new Label { Text = "按程序双向过滤 · 阻断本地代理连接 · 规则持续保留", AutoSize = true, ForeColor = Color.FromArgb(91, 106, 128), Location = new Point(2, 48) });
            layout.Controls.Add(heading, 0, 0);

            healthLabel.Dock = DockStyle.Fill;
            healthLabel.Padding = new Padding(12, 10, 8, 8);
            healthLabel.BackColor = Color.FromArgb(232, 239, 252);
            healthLabel.Text = "正在检查 Windows 防火墙…";
            healthLabel.Margin = new Padding(0, 3, 0, 9);
            layout.Controls.Add(healthLabel, 0, 1);

            FlowLayoutPanel toolbar = new FlowLayoutPanel { Dock = DockStyle.Fill, WrapContents = false, Margin = new Padding(0), Padding = new Padding(0, 2, 0, 0) };
            toolbar.Controls.Add(MakeButton("＋ 选择 EXE", 143, async delegate { await PickFiles(); }, false));
            toolbar.Controls.Add(MakeButton("扫描软件文件夹", 165, async delegate { await PickFolder(); }, false));
            toolbar.Controls.Add(MakeButton("全部勾选", 110, delegate { SetChecks(true); }, false));
            toolbar.Controls.Add(MakeButton("取消勾选", 110, delegate { SetChecks(false); }, false));
            toolbar.Controls.Add(MakeButton("刷新规则", 110, async delegate { await RefreshSafe(); }, false));
            layout.Controls.Add(toolbar, 0, 2);

            grid.Dock = DockStyle.Fill;
            grid.BackgroundColor = Color.White;
            grid.BorderStyle = BorderStyle.None;
            grid.AllowUserToAddRows = false;
            grid.AllowUserToDeleteRows = false;
            grid.AllowUserToResizeRows = false;
            grid.RowHeadersVisible = false;
            grid.AutoGenerateColumns = false;
            grid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
            grid.MultiSelect = false;
            grid.EnableHeadersVisualStyles = false;
            grid.ColumnHeadersHeight = 42;
            grid.ColumnHeadersHeightSizeMode = DataGridViewColumnHeadersHeightSizeMode.DisableResizing;
            grid.ColumnHeadersDefaultCellStyle.BackColor = Color.FromArgb(232, 237, 245);
            grid.ColumnHeadersDefaultCellStyle.ForeColor = ink;
            grid.ColumnHeadersDefaultCellStyle.Font = new Font(Font, FontStyle.Bold);
            grid.DefaultCellStyle.SelectionBackColor = Color.FromArgb(224, 234, 255);
            grid.DefaultCellStyle.SelectionForeColor = ink;
            grid.DefaultCellStyle.Padding = new Padding(4);
            grid.RowTemplate.Height = 42;
            grid.GridColor = Color.FromArgb(235, 239, 245);
            grid.AlternatingRowsDefaultCellStyle.BackColor = Color.FromArgb(249, 251, 254);
            grid.Columns.Add(new DataGridViewCheckBoxColumn { Name = "Pick", HeaderText = "选", Width = 44, Resizable = DataGridViewTriState.False });
            grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "App", HeaderText = "程序", Width = 168, ReadOnly = true });
            grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "State", HeaderText = "本工具规则", Width = 208, ReadOnly = true });
            grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "Path", HeaderText = "完整路径", AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill, MinimumWidth = 260, ReadOnly = true });
            grid.CurrentCellDirtyStateChanged += delegate { if (grid.IsCurrentCellDirty) grid.CommitEdit(DataGridViewDataErrorContexts.Commit); };
            grid.DataError += delegate(object sender, DataGridViewDataErrorEventArgs e) { e.ThrowException = false; };
            grid.Margin = new Padding(0);
            layout.Controls.Add(grid, 0, 3);

            FlowLayoutPanel actions = new FlowLayoutPanel { Dock = DockStyle.Fill, WrapContents = false, Margin = new Padding(0), Padding = new Padding(0, 12, 0, 0) };
            actions.Controls.Add(MakeButton("加强禁网（含本地代理）", 242, async delegate { await Apply(true); }, true));
            actions.Controls.Add(MakeButton("解除勾选程序禁网", 202, async delegate { await Apply(false); }, false));
            actions.Controls.Add(MakeButton("打开防火墙设置", 176, delegate { OpenFirewall(); }, false));
            layout.Controls.Add(actions, 0, 4);

            Label note = new Label { Dock = DockStyle.Fill, Text = "加强禁网也会阻断本机 TCP / UDP 通信，可能影响插件或软件内部协作。关闭工具后规则仍保留。\n其他帮助程序需要单独添加；操作后请重启目标软件。断网不会清除已保存的授权状态或内置弹窗。", ForeColor = Color.FromArgb(94, 108, 129), Padding = new Padding(0, 11, 0, 0), Margin = new Padding(0), Font = new Font(Font.FontFamily, 9F) };
            layout.Controls.Add(note, 0, 5);
            resultLabel.Dock = DockStyle.Fill;
            resultLabel.Text = "先选择 EXE，或扫描该软件的安装文件夹。";
            resultLabel.TextAlign = ContentAlignment.MiddleLeft;
            resultLabel.AutoEllipsis = true;
            resultLabel.Margin = new Padding(0);
            layout.Controls.Add(resultLabel, 0, 6);
            Shown += async delegate
            {
                if (preview)
                {
                    healthLabel.Text = "防火墙已开启    域：已开启    专用：已开启（当前）    公用：已开启";
                    AddPath(@"D:\Apps\LocalEditor\LocalEditor.exe", true, "加强禁网已就绪");
                    AddPath(@"D:\Apps\LocalEditor\Updater.exe", true, "待禁网");
                    AddPath(@"D:\Apps\LocalEditor\AdHelper.exe", true, "待禁网");
                    resultLabel.Text = "界面示例：勾选主程序、更新器和广告组件，一起禁网。";
                }
                else await RefreshSafe();
            };
            FormClosing += delegate(object sender, FormClosingEventArgs e)
            {
                if (busy) { e.Cancel = true; resultLabel.Text = "正在完成操作，请稍候再关闭。"; }
            };
        }

        private Button MakeButton(string text, int width, EventHandler handler, bool primary)
        {
            Button button = new Button { Text = text, Width = width, Height = 38, FlatStyle = FlatStyle.Flat, BackColor = primary ? blue : Color.White, ForeColor = primary ? Color.White : ink, Margin = new Padding(0, 0, 10, 0), Cursor = Cursors.Hand, UseVisualStyleBackColor = false };
            button.FlatAppearance.BorderColor = primary ? blue : Color.FromArgb(203, 213, 229);
            button.Click += handler;
            buttons.Add(button);
            return button;
        }

        private void SetBusy(bool value)
        {
            busy = value;
            foreach (Button button in buttons) button.Enabled = !value;
            grid.Enabled = !value;
            UseWaitCursor = value;
        }

        private void SetChecks(bool value) { foreach (DataGridViewRow row in grid.Rows) row.Cells[0].Value = value; }

        private void AddPath(string input, bool selected, string status)
        {
            string path = Firewall.Normalize(input);
            foreach (DataGridViewRow row in grid.Rows)
            {
                if (String.Equals((string)row.Cells[3].Value, path, StringComparison.OrdinalIgnoreCase))
                {
                    if (selected) row.Cells[0].Value = true;
                    return;
                }
            }
            int index = grid.Rows.Add(selected, Path.GetFileName(path), status, path);
            grid.Rows[index].Cells[3].ToolTipText = path;
        }

        private async Task PickFiles()
        {
            using (OpenFileDialog dialog = new OpenFileDialog { Title = "选择要禁止联网的程序（可以多选）", Filter = "Windows 程序 (*.exe)|*.exe", Multiselect = true, CheckFileExists = true })
            {
                if (dialog.ShowDialog(this) != DialogResult.OK) return;
                foreach (string path in dialog.FileNames) AddPath(path, true, "待禁网");
            }
            await RefreshSafe();
            resultLabel.Text = "已加入并勾选。点击“加强禁网（含本地代理）”才会写入规则。";
        }

        private async Task PickFolder()
        {
            using (FolderBrowserDialog dialog = new FolderBrowserDialog { Description = "选择该软件自己的安装文件夹（包含子文件夹）；扫描后可取消勾选。", ShowNewFolderButton = false })
            {
                if (dialog.ShowDialog(this) != DialogResult.OK) return;
                string root = Path.GetFullPath(dialog.SelectedPath).TrimEnd(Path.DirectorySeparatorChar);
                string[] broad = { Path.GetPathRoot(root).TrimEnd(Path.DirectorySeparatorChar), Environment.GetFolderPath(Environment.SpecialFolder.Windows), Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) };
                if (broad.Any(x => String.Equals(root, x, StringComparison.OrdinalIgnoreCase)))
                {
                    MessageBox.Show(this, "请进入具体软件的文件夹再扫描，避免误选大量无关程序。", "请选择软件目录");
                    return;
                }
                SetBusy(true);
                resultLabel.Text = "正在查找 EXE，较大的文件夹可能需要一点时间…";
                try
                {
                    List<string> found = new List<string>();
                    int skipped = 0;
                    await Task.Run(delegate
                    {
                        Stack<string> folders = new Stack<string>();
                        folders.Push(root);
                        while (folders.Count > 0)
                        {
                            string folder = folders.Pop();
                            try
                            {
                                foreach (string file in Directory.EnumerateFiles(folder, "*.exe"))
                                {
                                    if ((File.GetAttributes(file) & FileAttributes.ReparsePoint) != 0) { skipped++; continue; }
                                    found.Add(file);
                                    if (found.Count > 1000) throw new InvalidOperationException("找到的 EXE 超过 1000 个，请选择更小的具体软件文件夹。");
                                }
                                foreach (string child in Directory.EnumerateDirectories(folder))
                                {
                                    if ((File.GetAttributes(child) & FileAttributes.ReparsePoint) == 0) folders.Push(child);
                                    else skipped++;
                                }
                            }
                            catch (UnauthorizedAccessException) { skipped++; }
                            catch (IOException) { skipped++; }
                        }
                    });
                    foreach (string file in found.OrderBy(x => x)) AddPath(file, true, "待禁网");
                    await RefreshCore();
                    resultLabel.Text = "找到 " + found.Count + " 个 EXE，跳过 " + skipped + " 个不可读路径或链接。请检查勾选项后点击禁网。";
                }
                catch (Exception e) { ShowError(e); }
                finally { SetBusy(false); }
            }
        }

        private async Task RefreshCore()
        {
            List<FirewallEntry> entries = null;
            FirewallHealth health = null;
            await Task.Run(delegate
            {
                health = Firewall.Health(); entries = Firewall.List();
                Dictionary<string, int> strong = StrongFirewall.List();
                foreach (FirewallEntry entry in entries)
                {
                    int mask;
                    if (strong.TryGetValue(entry.Path, out mask)) entry.Status = mask == 15 ? "加强禁网已就绪" : "加强规则不完整";
                    else if (entry.Status == "双向禁网规则已就绪") entry.Status = "普通禁网（不拦本地代理）";
                }
                foreach (KeyValuePair<string, int> item in strong)
                    if (!entries.Any(x => String.Equals(x.Path, item.Key, StringComparison.OrdinalIgnoreCase)))
                        entries.Add(new FirewallEntry { Path = item.Key, Status = item.Value == 15 ? "加强禁网已就绪" : "加强规则不完整" });
            });
            ready = health.Ready;
            healthLabel.Text = health.Text;
            healthLabel.BackColor = ready ? Color.FromArgb(229, 244, 237) : Color.FromArgb(255, 236, 206);
            if (!ready) resultLabel.Text = "警告：防火墙未全部开启或规则受策略限制。请在防火墙设置中检查，不能保证禁网生效。";
            Dictionary<string, string> states = entries.ToDictionary(x => x.Path, x => x.Status, StringComparer.OrdinalIgnoreCase);
            foreach (DataGridViewRow row in grid.Rows)
            {
                string state;
                string path = (string)row.Cells[3].Value;
                row.Cells[2].Value = states.TryGetValue(path, out state) ? state : "未设置本工具规则";
            }
            foreach (FirewallEntry entry in entries) AddPath(entry.Path, false, entry.Status);
        }

        private async Task RefreshSafe()
        {
            if (busy) return;
            SetBusy(true);
            try { await RefreshCore(); }
            catch (Exception e)
            {
                ready = false;
                healthLabel.Text = "无法读取防火墙，请检查 Windows 防火墙服务和权限。";
                healthLabel.BackColor = Color.FromArgb(255, 236, 206);
                ShowError(e);
            }
            finally { SetBusy(false); }
        }

        private async Task Apply(bool block)
        {
            grid.EndEdit();
            List<string> paths = grid.Rows.Cast<DataGridViewRow>().Where(x => Object.Equals(x.Cells[0].Value, true)).Select(x => (string)x.Cells[3].Value).ToList();
            if (paths.Count == 0) { resultLabel.Text = "请先勾选至少一个程序。"; return; }
            SetBusy(true);
            resultLabel.Text = block ? "正在写入双向规则及底层过滤规则，包括本地代理连接…" : "正在删除所选程序的普通规则和加强规则…";
            int successes = 0;
            List<string> errors = new List<string>();
            try
            {
                await Task.Run(delegate
                {
                    foreach (string path in paths)
                    {
                        try
                        {
                            if (block) { Firewall.Block(path); StrongFirewall.Block(path); }
                            else { StrongFirewall.Unblock(path); Firewall.Unblock(path); }
                            successes++;
                        }
                        catch (Exception e) { errors.Add(path + "\r\n" + e.Message); }
                    }
                });
                await RefreshCore();
                resultLabel.Text = (block ? "规则已保存：" : "规则已解除：") + successes + " 个程序；失败 " + errors.Count + " 个。" + (block && !ready ? " 防火墙状态异常，请检查后再使用。" : " 请重启目标软件。" );
                if (errors.Count > 0) MessageBox.Show(this, String.Join("\r\n\r\n", errors.Take(8)) + (errors.Count > 8 ? "\r\n其余失败项目请缩小选择后重试。" : ""), "部分程序操作失败", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
            catch (Exception e) { ShowError(e); }
            finally { SetBusy(false); }
        }

        private void ShowError(Exception e)
        {
            resultLabel.Text = "操作未完成：" + e.Message;
            MessageBox.Show(this, e.Message, "操作未完成", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }

        private void OpenFirewall()
        {
            try { Process.Start(new ProcessStartInfo("control.exe", "/name Microsoft.WindowsFirewall") { UseShellExecute = true }); }
            catch (Exception e) { ShowError(e); }
        }
    }
}
