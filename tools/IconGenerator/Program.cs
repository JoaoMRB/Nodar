// Gera src/Nodar.App/Assets/nodar.ico e os PNG do logótipo.
// Uso: dotnet run --project tools/IconGenerator -- src/Nodar.App/Assets

using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;

// Gera o ícone do Nodar: quadrado arredondado com gradiente (#7C6CFF → #4C8DFF) e o radar branco
// (mesma geometria do ícone "Icon.Radar" da app, em unidades de 24×24).
var outDir = args[0];
Directory.CreateDirectory(outDir);
int[] sizes = [16, 20, 24, 32, 40, 48, 64, 128, 256];
var pngs = new List<(int Size, byte[] Data)>();

foreach (var size in sizes)
{
    using var bmp = new Bitmap(size, size, PixelFormat.Format32bppArgb);
    using var g = Graphics.FromImage(bmp);
    g.SmoothingMode = SmoothingMode.AntiAlias;
    g.PixelOffsetMode = PixelOffsetMode.HighQuality;
    g.Clear(Color.Transparent);

    // Margem pequena para o quadrado não tocar nas bordas (aspeto consistente com ícones do Windows 11).
    float margin = size <= 24 ? 0.5f : size * 0.05f;
    var tile = new RectangleF(margin, margin, size - 2 * margin, size - 2 * margin);
    float radius = tile.Width * 0.30f;
    using var shape = RoundedRect(tile, radius);

    using (var gradient = new LinearGradientBrush(tile, Color.FromArgb(0x7C, 0x6C, 0xFF), Color.FromArgb(0x4C, 0x8D, 0xFF), 45f))
        g.FillPath(gradient, shape);

    // Brilho suave no topo (dá volume sem parecer "antigo").
    if (size >= 32)
    {
        var top = new RectangleF(tile.X, tile.Y, tile.Width, tile.Height * 0.55f);
        using var gloss = new LinearGradientBrush(top, Color.FromArgb(46, 255, 255, 255), Color.FromArgb(0, 255, 255, 255), 90f);
        var clip = g.Clip; g.SetClip(shape); g.FillRectangle(gloss, top); g.Clip = clip;
    }

    // Radar: escala para ocupar ~56% do quadrado (como na app: ícone de 20 px num quadrado de 36 px).
    float scale = tile.Width * 0.56f / 18f;                 // a geometria vai de 3 a 21 (18 unidades)
    PointF P(float x, float y) => new(tile.X + tile.Width / 2 + (x - 12) * scale, tile.Y + tile.Height / 2 + (y - 12) * scale);
    float stroke = (size <= 20 ? 2.8f : size <= 32 ? 2.4f : 2.0f) * scale;

    using var pen = new Pen(Color.White, stroke) { StartCap = LineCap.Round, EndCap = LineCap.Round, LineJoin = LineJoin.Round };
    RectangleF Circle(float r) { var c = P(12, 12); return new(c.X - r * scale, c.Y - r * scale, 2 * r * scale, 2 * r * scale); }

    g.DrawArc(pen, Circle(9f), -90f, -270f);        // M12 3 A9 9 0 1 0 21 12
    if (size >= 20)
        g.DrawArc(pen, Circle(4.5f), -90f, -270f);  // M12 7.5 A4.5 4.5 0 1 0 16.5 12 (omitido em 16 px para não empastelar)
    g.DrawLine(pen, P(12, 12), P(18.4f, 5.6f));     // ponteiro
    var dot = stroke * 0.75f;
    var c0 = P(12, 12);
    g.FillEllipse(Brushes.White, c0.X - dot, c0.Y - dot, 2 * dot, 2 * dot);

    using var ms = new MemoryStream();
    bmp.Save(ms, ImageFormat.Png);
    if (size is 256 or 128 or 64)
        File.WriteAllBytes(Path.Combine(outDir, $"nodar-{size}.png"), ms.ToArray());

    // Formato mais compatível: PNG só no 256; restantes em DIB 32 bits (BGRA, de baixo para cima + máscara AND).
    pngs.Add((size, size >= 256 ? ms.ToArray() : ToDib(bmp)));
}

static byte[] ToDib(Bitmap bmp)
{
    int w = bmp.Width, h = bmp.Height;
    var maskStride = ((w + 31) / 32) * 4;
    using var ms = new MemoryStream();
    using var bw = new BinaryWriter(ms);
    bw.Write(40); bw.Write(w); bw.Write(h * 2);               // BITMAPINFOHEADER (altura = XOR + AND)
    bw.Write((short)1); bw.Write((short)32); bw.Write(0);
    bw.Write(w * h * 4 + maskStride * h); bw.Write(0); bw.Write(0); bw.Write(0); bw.Write(0);
    for (var y = h - 1; y >= 0; y--)
        for (var x = 0; x < w; x++)
        {
            var c = bmp.GetPixel(x, y);
            bw.Write(c.B); bw.Write(c.G); bw.Write(c.R); bw.Write(c.A);
        }
    for (var y = h - 1; y >= 0; y--)
    {
        var row = new byte[maskStride];
        for (var x = 0; x < w; x++)
            if (bmp.GetPixel(x, y).A == 0)
                row[x / 8] |= (byte)(0x80 >> (x % 8));
        bw.Write(row);
    }
    return ms.ToArray();
}

// ICO com imagens PNG (suportado desde o Windows Vista).
using (var ico = new BinaryWriter(File.Create(Path.Combine(outDir, "nodar.ico"))))
{
    ico.Write((short)0); ico.Write((short)1); ico.Write((short)pngs.Count);
    var offset = 6 + 16 * pngs.Count;
    foreach (var (size, data) in pngs)
    {
        ico.Write((byte)(size >= 256 ? 0 : size)); ico.Write((byte)(size >= 256 ? 0 : size));
        ico.Write((byte)0); ico.Write((byte)0); ico.Write((short)1); ico.Write((short)32);
        ico.Write(data.Length); ico.Write(offset);
        offset += data.Length;
    }
    foreach (var (_, data) in pngs) ico.Write(data);
}
Console.WriteLine($"ícone com {pngs.Count} tamanhos em {outDir}");

static GraphicsPath RoundedRect(RectangleF r, float radius)
{
    var d = radius * 2;
    var path = new GraphicsPath();
    path.AddArc(r.X, r.Y, d, d, 180, 90);
    path.AddArc(r.Right - d, r.Y, d, d, 270, 90);
    path.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
    path.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
    path.CloseFigure();
    return path;
}
