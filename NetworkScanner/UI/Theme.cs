namespace NetworkScanner.UI;

public static class Theme
{
    public static readonly Color Background = Color.FromArgb(8, 14, 28);
    public static readonly Color Surface = Color.FromArgb(20, 30, 48);
    public static readonly Color SurfaceLight = Color.FromArgb(31, 42, 63);
    public static readonly Color Border = Color.FromArgb(58, 72, 102);
    public static readonly Color Text = Color.FromArgb(242, 246, 255);
    public static readonly Color TextMuted = Color.FromArgb(152, 166, 202);
    public static readonly Color Primary = Color.FromArgb(88, 160, 255);
    public static readonly Color PrimaryHover = Color.FromArgb(62, 132, 230);
    public static readonly Color Success = Color.FromArgb(34, 197, 94);
    public static readonly Color Warning = Color.FromArgb(250, 204, 21);
    public static readonly Color Danger = Color.FromArgb(239, 68, 68);

    public static Font TitleFont => new("Segoe UI Semibold", 15F, FontStyle.Bold);
    public static Font SubtitleFont => new("Segoe UI", 9.2F);
    public static Font BodyFont => new("Segoe UI", 9.5F);
    public static Font SmallFont => new("Segoe UI", 8.5F);
    public static Font ButtonFont => new("Segoe UI Semibold", 9.2F);

    public static void StyleButton(Button btn, bool primary = false)
    {
        btn.FlatStyle = FlatStyle.Flat;
        btn.FlatAppearance.BorderSize = 0;
        btn.Font = ButtonFont;
        btn.Cursor = Cursors.Hand;
        btn.Padding = new Padding(12, 6, 12, 6);
        btn.Margin = new Padding(2);

        if (primary)
        {
            btn.BackColor = Primary;
            btn.ForeColor = Color.White;
            btn.FlatAppearance.MouseOverBackColor = PrimaryHover;
        }
        else
        {
            btn.BackColor = SurfaceLight;
            btn.ForeColor = Text;
            btn.FlatAppearance.MouseOverBackColor = Border;
        }
    }

    public static void StyleDataGridView(DataGridView grid)
    {
        grid.BackgroundColor = Surface;
        grid.BorderStyle = BorderStyle.None;
        grid.CellBorderStyle = DataGridViewCellBorderStyle.SingleHorizontal;
        grid.ColumnHeadersBorderStyle = DataGridViewHeaderBorderStyle.None;
        grid.EnableHeadersVisualStyles = false;
        grid.GridColor = Border;
        grid.RowHeadersVisible = false;
        grid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
        grid.MultiSelect = false;
        grid.ReadOnly = true;
        grid.AllowUserToAddRows = false;
        grid.AllowUserToDeleteRows = false;
        grid.AllowUserToResizeRows = false;
        grid.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill;
        grid.RowTemplate.Height = 36;

        grid.DefaultCellStyle.BackColor = Surface;
        grid.DefaultCellStyle.ForeColor = Text;
        grid.DefaultCellStyle.SelectionBackColor = Color.FromArgb(40, 60, 100);
        grid.DefaultCellStyle.SelectionForeColor = Text;
        grid.DefaultCellStyle.Font = BodyFont;
        grid.DefaultCellStyle.Padding = new Padding(8, 4, 8, 4);

        grid.AlternatingRowsDefaultCellStyle.BackColor = SurfaceLight;

        grid.ColumnHeadersDefaultCellStyle.BackColor = Background;
        grid.ColumnHeadersDefaultCellStyle.ForeColor = TextMuted;
        grid.ColumnHeadersDefaultCellStyle.Font = new Font("Segoe UI Semibold", 8.5F);
        grid.ColumnHeadersDefaultCellStyle.Padding = new Padding(8, 8, 8, 8);
        grid.ColumnHeadersHeight = 40;
    }

    public static void StyleCheckBox(CheckBox cb)
    {
        cb.ForeColor = Text;
        cb.Font = BodyFont;
        cb.BackColor = Color.Transparent;
    }

    public static Panel CreateInfoCard(string label, string value)
    {
        var panel = new Panel
        {
            BackColor = Surface,
            Padding = new Padding(14, 10, 14, 10),
            Margin = new Padding(4),
            MinimumSize = new Size(150, 76),
            BorderStyle = BorderStyle.FixedSingle
        };

        var lblTitle = new Label
        {
            Text = label.ToUpperInvariant(),
            ForeColor = TextMuted,
            Font = SmallFont,
            AutoSize = true,
            Location = new Point(14, 10)
        };

        var lblValue = new Label
        {
            Text = value,
            ForeColor = Text,
            Font = new Font("Segoe UI Semibold", 10.2F),
            AutoSize = true,
            Location = new Point(14, 30),
            MaximumSize = new Size(200, 0)
        };

        panel.Controls.Add(lblTitle);
        panel.Controls.Add(lblValue);
        panel.Tag = lblValue;

        return panel;
    }

    public static void UpdateInfoCard(Panel panel, string value)
    {
        if (panel.Tag is Label lbl)
            lbl.Text = value;
    }
}
