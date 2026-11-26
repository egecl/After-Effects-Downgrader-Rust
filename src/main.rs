#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
use eframe::egui;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::Arc;

macro_rules! safe_println { ($($arg:tt)*) => {{ use std::io::Write as _; let stdout = std::io::stdout(); let mut lock = stdout.lock(); let _ = writeln!(lock, $($arg)*); }}; }
macro_rules! safe_eprintln { ($($arg:tt)*) => {{ use std::io::Write as _; let stderr = std::io::stderr(); let mut lock = stderr.lock(); let _ = writeln!(lock, $($arg)*); }}; }

const VERSIONS: &[(u16, u8)] = &[
    (2025, 0x60), (2024, 0x5f), (2023, 0x5e), (2022, 0x5d),
    (2021, 0x5c), (2020, 0x5b), (2019, 0x5a), (2018, 0x59),
];
const SIGNATURES: &[(u8, [u8; 6])] = &[
    (0x60, [0x60, 0x01, 0x0f, 0x08, 0x86, 0x44]),
    (0x5f, [0x5f, 0x05, 0x0f, 0x02, 0x86, 0x34]),
    (0x5e, [0x5e, 0x09, 0x0b, 0x3b, 0x06, 0x37]),
    (0x5d, [0x5d, 0x2b, 0x0b, 0x33, 0x06, 0x3b]),
];

#[derive(Debug)]
struct AepInfo {
    file_size: usize,
    container_offset: Option<usize>,
    form_offset: Option<usize>,
    head_offset: Option<usize>,
    head_size: Option<usize>,
    version_byte: Option<u8>,
    version_year: Option<u16>,
    signature: Option<[u8; 6]>,
    signature_known: bool,
}

fn find_bytes(data: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || from > data.len() { return None; }
    data[from..].windows(needle.len()).position(|w| w == needle).map(|p| p + from)
}

fn find_container(data: &[u8], magic: &[u8]) -> Option<usize> {
    let mut search_from = 0;
    while let Some(pos) = find_bytes(data, magic, search_from) {
        if pos.checked_add(12).is_some_and(|end| end <= data.len())
            && &data[pos + 8..pos + 12] == b"Egg!"
        { return Some(pos); }
        search_from = pos.saturating_add(1);
    }
    None
}

fn find_head_chunk(data: &[u8], start: usize) -> Option<(usize, usize)> {
    let mut search_from = start.checked_add(4)?;
    while let Some(pos) = find_bytes(data, b"head", search_from) {
        if let Some(size_end) = pos.checked_add(8).filter(|end| *end <= data.len()) {
            let size = u32::from_be_bytes(data[pos + 4..size_end].try_into().ok()?) as usize;
            if size >= 8 && size_end.checked_add(size).is_some_and(|end| end <= data.len()) { return Some((pos, size)); }
        }
        search_from = pos.saturating_add(1);
    }
    None
}

fn analyze(data: &[u8]) -> AepInfo {
    let container = [b"RIFX".as_slice(), b"RIFF".as_slice()].iter().find_map(|magic| find_container(data, magic));
    let form = container.map(|p| p + 8);
    let head = form.and_then(|p| find_head_chunk(data, p));
    let (head_offset, head_size) = head.map_or((None, None), |(p, s)| (Some(p), Some(s)));
    let version_byte = head.and_then(|(p, s)| (s >= 8).then(|| data[p + 9]));
    let version_year = version_byte.and_then(|b| VERSIONS.iter().find(|(_, byte)| *byte == b).map(|(year, _)| *year));
    let signature = head.and_then(|(p, s)| (s >= 8).then(|| data[p + 10..p + 16].try_into().unwrap()));
    let signature_known = version_byte.zip(signature).is_some_and(|(byte, found)| SIGNATURES.iter().any(|(known, expected)| *known == byte && *expected == found));
    AepInfo { file_size: data.len(), container_offset: container, form_offset: form, head_offset, head_size, version_byte, version_year, signature, signature_known }
}

fn hex_offset(value: Option<usize>) -> String { value.map_or_else(|| "NOT FOUND".into(), |v| format!("0x{v:X}")) }
fn signature_hex(sig: Option<[u8; 6]>) -> String { sig.map_or_else(|| "N/A".into(), |s| s.iter().map(|b| format!("{b:02X}")).collect()) }
fn target_byte(year: u16) -> Option<u8> { VERSIONS.iter().find(|(y, _)| *y == year).map(|(_, b)| *b) }
fn usage() -> &'static str {
    "AE Project Binary Downgrader\n\nUSAGE:\n  ae-downgrade-toolkit-rust analyze <file.aep>\n  ae-downgrade-toolkit-rust patch <input.aep> [-o <output.aep>] -t <year> [--dry-run] [--force]\n  ae-downgrade-toolkit-rust batch <input_dir> <output_dir> -t <year> [--dry-run] [--force]\n\nSupported years: 2018, 2019, 2020, 2021, 2022, 2023, 2024, 2025\nThis changes header metadata only; it does not convert project features."
}

fn analyze_file(path: &Path) -> Result<(Vec<u8>, AepInfo), String> {
    let data = fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let info = analyze(&data);
    Ok((data, info))
}
fn show_analysis(path: &Path, info: &AepInfo) {
    safe_println!("File: {}", path.display());
    safe_println!("Size: {} bytes", info.file_size);
    safe_println!("RIFX/RIFF header: {}", hex_offset(info.container_offset));
    safe_println!("Egg! form:         {}", hex_offset(info.form_offset));
    safe_println!("head chunk:        {}{}", hex_offset(info.head_offset), info.head_size.map_or(String::new(), |s| format!(" (size: {s})")));
    safe_println!("Version byte:      {}", info.version_byte.map_or_else(|| "NOT FOUND".into(), |b| format!("0x{b:02X}")));
    safe_println!("Detected AE:       {}", info.version_year.map_or_else(|| "Unknown".into(), |y| y.to_string()));
    safe_println!("Signature:         {} ({})", signature_hex(info.signature), if info.signature_known { "known" } else { "unknown" });
}
fn same_path(input: &Path, output: &Path) -> bool {
    let (Ok(input), Ok(output)) = (fs::canonicalize(input), fs::canonicalize(output)) else { return false; };
    #[cfg(windows)]
    { input.to_string_lossy().eq_ignore_ascii_case(&output.to_string_lossy()) }
    #[cfg(not(windows))]
    { input == output }
}
fn patch(input: &Path, output: &Path, year: u16, dry_run: bool, force: bool) -> Result<bool, String> {
    let target = target_byte(year).ok_or_else(|| format!("unsupported target year: {year}"))?;
    let (mut data, info) = analyze_file(input)?;
    if same_path(input, output) { return Err("Input and output must be different files to preserve the original.".into()); }
    let container = info.container_offset.ok_or_else(|| format!("{} is not a valid RIFX/RIFF Egg! file", input.display()))?;
    let head = info.head_offset.ok_or_else(|| "'head' chunk not found or invalid".to_string())?;
    let current = info.version_byte.ok_or_else(|| "could not read major version byte".to_string())?;
    safe_println!("File: {}", input.file_name().unwrap_or_default().to_string_lossy());
    safe_println!("Format: {}", if &data[container..container + 4] == b"RIFF" { "RIFF (big-endian)" } else { "RIFX (little-endian)" });
    safe_println!("Header at: 0x{container:X}");
    safe_println!("head chunk at: 0x{head:X} (size: {})", info.head_size.unwrap());
    safe_println!("Current version byte: 0x{current:02X} -> AE {}", info.version_year.map_or_else(|| "unknown".into(), |y| y.to_string()));
    safe_println!("Signature: {} ({})", signature_hex(info.signature), if info.signature_known { "known" } else { "unknown" });
    if info.version_year == Some(year) && !force { safe_println!("Already target version {year}; skipped (use --force to patch anyway)."); return Ok(false); }
    safe_println!("Target version byte: 0x{target:02X} -> AE {year}");
    if dry_run { safe_println!("[DRY RUN] Would patch byte at offset 0x{:X}", head + 9); return Ok(true); }
    data[head + 9] = target;
    if let Some((_, signature)) = SIGNATURES.iter().find(|(b, _)| *b == target) {
        data[head + 10..head + 16].copy_from_slice(signature);
        safe_println!("Also updated signature to: {}", signature_hex(Some(*signature)));
    }
    fs::write(output, data).map_err(|e| format!("could not write {}: {e}", output.display()))?;
    safe_println!("Saved to: {}", output.display());
    Ok(true)
}
fn parse_year(args: &[String]) -> Result<u16, String> {
    let mut i = 0;
    while i < args.len() {
        if args[i] == "-t" || args[i] == "--target" {
            let value = args.get(i + 1).ok_or("missing year after target flag")?;
            let year = value.parse::<u16>().map_err(|_| format!("invalid target year: {value}"))?;
            if target_byte(year).is_none() { return Err(format!("unsupported target year {year}")); }
            return Ok(year);
        }
        i += 1;
    }
    Err("required target flag: -t <year>".into())
}
fn has_flag(args: &[String], flag: &str) -> bool { args.iter().any(|a| a == flag) }
fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    let command = args.first().ok_or_else(|| usage().to_string())?.as_str();
    match command {
        "analyze" => {
            let file = args.get(1).ok_or("missing input file")?;
            let (_, info) = analyze_file(Path::new(file))?;
            show_analysis(Path::new(file), &info);
        }
        "patch" => {
            let input = args.get(1).ok_or("missing input file")?;
            let year = parse_year(&args)?;
            let output = args.windows(2).find(|w| w[0] == "-o" || w[0] == "--output").map(|w| PathBuf::from(&w[1])).unwrap_or_else(|| {
                let path = Path::new(input);
                let stem = path.file_stem().unwrap_or_default().to_string_lossy();
                let ext = path.extension().map_or_else(|| "aep".into(), |e| e.to_string_lossy());
                PathBuf::from(format!("{stem}_v{year}.{ext}"))
            });
            patch(Path::new(input), &output, year, has_flag(&args, "--dry-run"), has_flag(&args, "--force"))?;
        }
        "batch" => {
            let input_dir = Path::new(args.get(1).ok_or("missing input directory")?);
            let output_dir = Path::new(args.get(2).ok_or("missing output directory")?);
            let year = parse_year(&args)?;
            let dry_run = has_flag(&args, "--dry-run");
            let force = has_flag(&args, "--force");
            if !input_dir.is_dir() { return Err(format!("input directory does not exist: {}", input_dir.display())); }
            if !dry_run { fs::create_dir_all(output_dir).map_err(|e| format!("could not create output directory: {e}"))?; }
            let mut files = fs::read_dir(input_dir).map_err(|e| e.to_string())?.filter_map(Result::ok).map(|e| e.path()).filter(|p| p.is_file() && p.extension().is_some_and(|e| e.eq_ignore_ascii_case("aep"))).collect::<Vec<_>>();
            files.sort();
            if files.is_empty() { safe_println!("No .aep files found."); return Ok(()); }
            safe_println!("Target: AE {year} (version byte 0x{:02X})", target_byte(year).unwrap());
            safe_println!("Input:  {}\nOutput: {}\nDry run: {}\n", input_dir.display(), output_dir.display(), dry_run);
            let mut successes = 0;
            for file in files {
                safe_println!("Processing: {}", file.file_name().unwrap_or_default().to_string_lossy());
                let stem = file.file_stem().unwrap_or_default().to_string_lossy();
                let ext = file.extension().unwrap_or_default().to_string_lossy();
                let destination = output_dir.join(format!("{stem}_v{year}.{ext}"));
                match patch(&file, &destination, year, dry_run, force) {
                    Ok(true) => successes += 1,
                    Ok(false) => {},
                    Err(e) => safe_eprintln!("  FAILED: {e}"),
                }
            }
            safe_println!("\n=== Summary ===\n{successes}/{} files processed successfully.", fs::read_dir(input_dir).map_err(|e| e.to_string())?.filter_map(Result::ok).filter(|e| e.path().is_file() && e.path().extension().is_some_and(|x| x.eq_ignore_ascii_case("aep"))).count());
        }
        "--help" | "-h" | "help" => safe_println!("{}", usage()),
        _ => return Err(format!("unknown command: {command}\n\n{}", usage())),
    }
    Ok(())
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Language { English, Turkish }

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode { Single, Batch }

struct DowngraderApp {
    mode: Mode,
    input: String,
    output: String,
    year: u16,
    dry_run: bool,
    force: bool,
    status_en: String,
    status_tr: String,
    details_en: String,
    details_tr: String,
    kind: bool,
    language: Language,
    cursor_glow: Option<egui::Pos2>,
    glow_alpha: f32,
    intro_elapsed: f32,
}

impl Default for DowngraderApp {
    fn default() -> Self {
        Self { mode: Mode::Single, input: String::new(), output: String::new(), year: 2023,
            dry_run: false, force: false, status_en: "Choose an After Effects project to get started.".into(), status_tr: "Başlamak için bir After Effects projesi seçin.".into(), details_en: String::new(), details_tr: String::new(), kind: false, language: Language::English, cursor_glow: None, glow_alpha: 0.0, intro_elapsed: 0.0 }
    }
}

impl DowngraderApp {
    fn set_status(&mut self, english: impl Into<String>, turkish: impl Into<String>, kind: bool) {
        self.status_en = english.into();
        self.status_tr = turkish.into();
        self.kind = kind;
    }
    fn status_text(&self) -> &str {
        match self.language { Language::English => &self.status_en, Language::Turkish => &self.status_tr }
    }
    fn details_text(&self) -> &str {
        match self.language { Language::English => &self.details_en, Language::Turkish => &self.details_tr }
    }
    fn pick_input(&mut self) {
        if self.mode == Mode::Single {
            if let Some(path) = rfd::FileDialog::new().add_filter(phrase(self.language, "After Effects project", "After Effects projesi"), &["aep"]).pick_file() {
                self.input = path.display().to_string();
                let default = path.with_file_name(format!("{}_v{}.aep", path.file_stem().unwrap_or_default().to_string_lossy(), self.year));
                self.output = default.display().to_string();
                self.inspect();
            }
        } else if let Some(path) = rfd::FileDialog::new().pick_folder() {
            self.input = path.display().to_string();
        }
    }
    fn pick_output(&mut self) {
        if self.mode == Mode::Batch {
            if let Some(path) = rfd::FileDialog::new().pick_folder() { self.output = path.display().to_string(); }
        } else if let Some(path) = rfd::FileDialog::new().add_filter(phrase(self.language, "After Effects project", "After Effects projesi"), &["aep"]).save_file() {
            self.output = path.display().to_string();
        }
    }
    fn inspect(&mut self) {
        if self.input.trim().is_empty() {
            self.set_status("Choose a project file first.", "Önce bir proje dosyası seçin.", true);
            return;
        }
        match analyze_file(Path::new(self.input.trim())) {
            Ok((_, info)) => {
                let valid = info.container_offset.is_some() && info.head_offset.is_some();
                self.details_en = format!("{}  ·  {}  ·  AE {}", if valid { "Valid project header" } else { "Header not recognized" }, format_size(info.file_size, Language::English), info.version_year.map_or_else(|| "version unknown".to_string(), |v| v.to_string()));
                self.details_tr = format!("{}  ·  {}  ·  AE {}", if valid { "Geçerli proje başlığı" } else { "Proje başlığı tanınmadı" }, format_size(info.file_size, Language::Turkish), info.version_year.map_or_else(|| "sürüm bilinmiyor".to_string(), |v| v.to_string()));
                if info.head_offset.is_some() {
                    self.set_status("Project analyzed. Choose a target version when ready.", "Proje analiz edildi. Hazır olduğunuzda hedef sürümü seçin.", false);
                } else {
                    self.set_status("This file does not contain a recognized After Effects header.", "Bu dosyada tanınan bir After Effects başlığı bulunamadı.", true);
                }
            }
            Err(error) => {
                self.set_status(format!("Analysis failed: {error}"), "Analiz başarısız. Dosya yolunu ve erişim izinlerini kontrol edin.", true);
                self.details_en.clear(); self.details_tr.clear();
            }
        }
    }
    fn process(&mut self) {
        if self.input.trim().is_empty() {
            self.set_status("Choose an input file or folder first.", "Önce bir kaynak dosya veya klasör seçin.", true);
            return;
        }
        if self.output.trim().is_empty() {
            self.set_status("Choose where the output should be saved.", "Çıktının kaydedileceği konumu seçin.", true);
            return;
        }
        if self.mode == Mode::Single {
            match patch(Path::new(self.input.trim()), Path::new(self.output.trim()), self.year, self.dry_run, self.force) {
                Ok(true) if self.dry_run => self.set_status(format!("Dry run complete. Ready to write the AE {} copy.", self.year), format!("Önizleme tamamlandı. AE {} kopyası oluşturulmaya hazır.", self.year), false),
                Ok(true) => self.set_status(format!("Done. Your AE {} copy was saved successfully.", self.year), format!("Tamamlandı. AE {} kopyası başarıyla kaydedildi.", self.year), false),
                Ok(false) => self.set_status(format!("No changes made. This project is already marked as AE {}.", self.year), format!("Değişiklik yapılmadı. Bu proje zaten AE {} olarak işaretli.", self.year), false),
                Err(error) => self.set_status(format!("Operation failed: {error}"), "İşlem başarısız. Dosya yolunu ve erişim izinlerini kontrol edin.", true),
            }
        } else {
            match batch_gui(Path::new(self.input.trim()), Path::new(self.output.trim()), self.year, self.dry_run, self.force) {
                Ok((done, total, failed)) => self.set_status(format!("Finished: {done} of {total} projects processed{}.", if failed > 0 { format!(", {failed} failed or skipped") } else { String::new() }), format!("Tamamlandı: {total} projeden {done} tanesi işlendi{}.", if failed > 0 { format!(", {failed} başarısız veya atlandı") } else { String::new() }), false),
                Err(error) if error == "No .aep files were found in that folder." => self.set_status(error, "Bu klasörde .aep dosyası bulunamadı.", true),
                Err(error) => self.set_status(format!("Batch operation failed: {error}"), "Toplu işlem başarısız. Girdi ve çıktı klasörlerini kontrol edin.", true),
            }
        }
    }
}
fn format_size(size: usize, language: Language) -> String {
    if size >= 1_048_576 { format!("{:.1} MB", size as f64 / 1_048_576.0) }
    else if size >= 1_024 { format!("{:.0} KB", size as f64 / 1_024.0) }
    else { match language { Language::English => format!("{size} bytes"), Language::Turkish => format!("{size} bayt") } }
}

fn batch_gui(input: &Path, output: &Path, year: u16, dry_run: bool, force: bool) -> Result<(usize, usize, usize), String> {
    if !input.is_dir() { return Err(format!("Input folder does not exist: {}", input.display())); }
    let mut files = fs::read_dir(input).map_err(|e| e.to_string())?.filter_map(Result::ok).map(|e| e.path())
        .filter(|p| p.is_file() && p.extension().is_some_and(|e| e.eq_ignore_ascii_case("aep"))).collect::<Vec<_>>();
    files.sort();
    let total = files.len();
    if total == 0 { return Err("No .aep files were found in that folder.".into()); }
    if !dry_run { fs::create_dir_all(output).map_err(|e| format!("Could not create output folder: {e}"))?; }
    let mut done = 0; let mut failed = 0;
    for file in files {
        let name = file.file_stem().unwrap_or_default().to_string_lossy();
        let destination = output.join(format!("{name}_v{year}.aep"));
        match patch(&file, &destination, year, dry_run, force) { Ok(true) => done += 1, Ok(false) => failed += 1, Err(e) => { safe_eprintln!("{}: {e}", file.display()); failed += 1; } }
    }
    Ok((done, total, failed))
}

fn phrase<'a>(language: Language, english: &'a str, turkish: &'a str) -> &'a str {
    match language { Language::English => english, Language::Turkish => turkish }
}
const PANEL2: egui::Color32 = egui::Color32::from_rgb(31, 35, 48);
const MUTED: egui::Color32 = egui::Color32::from_rgb(151, 158, 178);
const ACCENT: egui::Color32 = egui::Color32::from_rgb(161, 116, 255);

fn label(ui: &mut egui::Ui, text: &str) { ui.label(egui::RichText::new(text).color(MUTED).size(12.0)); }
fn blend(a: egui::Color32, b: egui::Color32, t: f32) -> egui::Color32 {
    let t = t.clamp(0.0, 1.0);
    egui::Color32::from_rgb(
        egui::lerp(a.r() as f32..=b.r() as f32, t) as u8,
        egui::lerp(a.g() as f32..=b.g() as f32, t) as u8,
        egui::lerp(a.b() as f32..=b.b() as f32, t) as u8,
    )
}

fn paint_quad_gradient(painter: &egui::Painter, rect: egui::Rect, colors: [egui::Color32; 4]) {
    let mut mesh = egui::Mesh::default();
    mesh.colored_vertex(rect.left_top(), colors[0]);
    mesh.colored_vertex(rect.right_top(), colors[1]);
    mesh.colored_vertex(rect.left_bottom(), colors[2]);
    mesh.colored_vertex(rect.right_bottom(), colors[3]);
    mesh.add_triangle(0, 1, 2);
    mesh.add_triangle(1, 3, 2);
    painter.add(egui::Shape::mesh(mesh));
}
fn paint_radial_glow(painter: &egui::Painter, center: egui::Pos2, radius: f32, rgb: [u8; 3], alpha: u8) {
    const SEGMENTS: usize = 48;
    let mut mesh = egui::Mesh::default();
    mesh.colored_vertex(center, egui::Color32::from_rgba_unmultiplied(rgb[0], rgb[1], rgb[2], alpha));
    for segment in 0..=SEGMENTS {
        let angle = std::f32::consts::TAU * segment as f32 / SEGMENTS as f32;
        let point = center + egui::vec2(angle.cos() * radius, angle.sin() * radius);
        mesh.colored_vertex(point, egui::Color32::from_rgba_unmultiplied(rgb[0], rgb[1], rgb[2], 0));
    }
    for segment in 0..SEGMENTS { mesh.add_triangle(0, segment as u32 + 1, segment as u32 + 2); }
    painter.add(egui::Shape::mesh(mesh));
}
fn animated_button(ui: &mut egui::Ui, text: &str, size: [f32; 2], color: egui::Color32, selected: bool) -> egui::Response {
    let (rect, response) = ui.allocate_exact_size(egui::vec2(size[0], size[1]), egui::Sense::click());
    let ctx = ui.ctx();
    let hover = ctx.animate_bool_with_time(response.id.with("hover"), response.hovered(), 0.20);
    let pressed = ctx.animate_bool_with_time(response.id.with("press"), response.is_pointer_button_down_on(), 0.12);
    let button_rect = rect.shrink(pressed * 1.0);
    let idle = if selected {
        if color == ACCENT { egui::Color32::from_rgb(113, 75, 156) }
        else { blend(color, egui::Color32::from_rgb(72, 48, 101), 0.32) }
    } else { egui::Color32::from_rgb(39, 34, 52) };
    let hovered = if selected { egui::Color32::from_rgb(132, 91, 176) } else { egui::Color32::from_rgb(53, 45, 69) };
    let fill = blend(idle, hovered, hover);
    let painter = ui.painter();
    painter.rect_filled(button_rect, 19, fill);
    let outline = if selected { egui::Color32::from_rgba_unmultiplied(211, 174, 244, 45) } else { egui::Color32::from_rgba_unmultiplied(190, 172, 215, (18.0 + hover * 16.0) as u8) };
    painter.rect_stroke(button_rect, 19, egui::Stroke::new(1.0_f32, outline), egui::StrokeKind::Inside);
    painter.text(button_rect.center(), egui::Align2::CENTER_CENTER, text, egui::FontId::proportional(13.0), egui::Color32::from_rgb(248, 242, 255));
    response
}
fn field_row(ui: &mut egui::Ui, title: &str, value: &mut String, button: &str, hint: &str) -> bool {
    label(ui, title); ui.add_space(7.0);
    let mut clicked = false;
    ui.horizontal(|ui| {
        let edit = egui::TextEdit::singleline(value).hint_text(hint).desired_width(ui.available_width() - 104.0);
        ui.add_sized([ui.available_width() - 100.0, 42.0], edit);
        clicked = animated_button(ui, button, [92.0, 42.0], PANEL2, false).clicked();
    });
    clicked
}

fn titlebar_control(ui: &mut egui::Ui, id: &str, close: bool, maximized: bool) -> egui::Response {
    let (rect, response) = ui.allocate_exact_size(egui::vec2(32.0, 28.0), egui::Sense::click());
    if response.hovered() {
        let color = if close { egui::Color32::from_rgb(174, 55, 78) } else { egui::Color32::from_rgba_unmultiplied(170, 145, 198, 42) };
        ui.painter().rect_filled(rect, 8, color);
    }
    let center = rect.center();
    let stroke = egui::Stroke::new(1.4_f32, egui::Color32::from_rgb(222, 211, 234));
    match id {
        "minimize" => { ui.painter().line_segment([center + egui::vec2(-5.0, 0.0), center + egui::vec2(5.0, 0.0)], stroke); }
        "maximize" => {
            let shape = egui::Rect::from_center_size(center, egui::vec2(9.0, 8.0));
            if maximized {
                ui.painter().rect_stroke(shape.translate(egui::vec2(-2.0, 2.0)), 1, stroke, egui::StrokeKind::Inside);
                ui.painter().rect_stroke(shape.translate(egui::vec2(2.0, -2.0)), 1, stroke, egui::StrokeKind::Inside);
            } else { ui.painter().rect_stroke(shape, 1, stroke, egui::StrokeKind::Inside); }
        }
        _ => {
            ui.painter().line_segment([center + egui::vec2(-4.0, -4.0), center + egui::vec2(4.0, 4.0)], stroke);
            ui.painter().line_segment([center + egui::vec2(4.0, -4.0), center + egui::vec2(-4.0, 4.0)], stroke);
        }
    }
    response
}
impl eframe::App for DowngraderApp {
    fn clear_color(&self, _visuals: &egui::Visuals) -> [f32; 4] { [14.0 / 255.0, 10.0 / 255.0, 20.0 / 255.0, 1.0] }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        ctx.style_mut(|style| {
            style.visuals.window_corner_radius = egui::CornerRadius::same(22);
            style.visuals.menu_corner_radius = egui::CornerRadius::same(18);
            style.visuals.widgets.noninteractive.corner_radius = egui::CornerRadius::same(14);
            style.visuals.widgets.inactive.corner_radius = egui::CornerRadius::same(14);
            style.visuals.widgets.hovered.corner_radius = egui::CornerRadius::same(16);
            style.visuals.widgets.active.corner_radius = egui::CornerRadius::same(16);
            style.visuals.widgets.open.corner_radius = egui::CornerRadius::same(16);
        });
        let dt = ctx.input(|input| input.stable_dt).clamp(1.0 / 240.0, 0.05);
        self.intro_elapsed = (self.intro_elapsed + dt).min(1.0);
        let linear = self.intro_elapsed;
        let reveal = linear * linear * (3.0 - 2.0 * linear);
        if reveal < 1.0 { ctx.request_repaint(); }
        let pointer = ctx.pointer_hover_pos();
        if let Some(target) = pointer {
            let current = self.cursor_glow.get_or_insert(target);
            *current = current.lerp(target, (dt * 16.0).clamp(0.0, 1.0));
        }
        let target_alpha = if pointer.is_some() { 1.0 } else { 0.0 };
        self.glow_alpha += (target_alpha - self.glow_alpha) * (dt * 8.0).clamp(0.0, 1.0);
        if (target_alpha - self.glow_alpha).abs() > 0.01 { ctx.request_repaint(); }
        let glow_center = self.cursor_glow;
        let glow_alpha = self.glow_alpha;
        let mut toggle_language = false;
        let language = self.language;
        let title = phrase(language, "AE Downgrader", "AE Sürüm Düşürücü");
        ctx.send_viewport_cmd(egui::ViewportCommand::Title(title.to_owned()));
        egui::CentralPanel::default().frame(egui::Frame::new().fill(egui::Color32::TRANSPARENT).inner_margin(egui::Margin::ZERO)).show(ctx, |ui| {
            let window_bounds = ctx.screen_rect();
            let background = ctx.layer_painter(egui::LayerId::background()).with_clip_rect(window_bounds);
            paint_quad_gradient(&background, window_bounds, [
                egui::Color32::from_rgb(27, 12, 34), egui::Color32::from_rgb(13, 9, 20),
                egui::Color32::from_rgb(10, 13, 25), egui::Color32::from_rgb(9, 8, 15),
            ]);
            let bounds = ui.max_rect();
            let painter = ui.painter().with_clip_rect(bounds);

            let glow_painter = painter.with_clip_rect(ctx.screen_rect());
            paint_radial_glow(&glow_painter, egui::pos2(bounds.right() - 170.0, bounds.top() + 90.0), 300.0, [112, 43, 158], 16);
            if let Some(center) = glow_center {
                paint_radial_glow(&glow_painter, center, 430.0, [163, 82, 230], (12.0 * glow_alpha).round() as u8);
                paint_radial_glow(&glow_painter, center + egui::vec2(24.0, 20.0), 330.0, [70, 111, 245], (5.0 * glow_alpha).round() as u8);
            }
            let titlebar_rect = egui::Rect::from_min_size(bounds.min, egui::vec2(bounds.width(), 38.0));
            painter.rect_filled(titlebar_rect, 0, egui::Color32::from_rgba_unmultiplied(27, 20, 36, 210));
            ui.horizontal(|ui| {
                let width = ui.available_width();
                let (drag_rect, drag_response) = ui.allocate_exact_size(egui::vec2((width - 112.0).max(180.0), 32.0), egui::Sense::click_and_drag());
                ui.painter().text(drag_rect.left_center() + egui::vec2(12.0, 0.0), egui::Align2::LEFT_CENTER, phrase(language, "AE Downgrader", "AE Sürüm Düşürücü"), egui::FontId::proportional(13.0), egui::Color32::from_rgb(222, 213, 233));
                if drag_response.drag_started() { ctx.send_viewport_cmd(egui::ViewportCommand::StartDrag); }
                if drag_response.double_clicked() { let maximized = ctx.input(|input| input.viewport().maximized.unwrap_or(false)); ctx.send_viewport_cmd(egui::ViewportCommand::Maximized(!maximized)); }
                ui.allocate_ui_with_layout(egui::vec2(104.0, 32.0), egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.spacing_mut().item_spacing.x = 4.0;
                    let maximized = ctx.input(|input| input.viewport().maximized.unwrap_or(false));
                    if titlebar_control(ui, "close", true, maximized).clicked() { ctx.send_viewport_cmd(egui::ViewportCommand::Close); }
                    if titlebar_control(ui, "maximize", false, maximized).clicked() { ctx.send_viewport_cmd(egui::ViewportCommand::Maximized(!maximized)); }
                    if titlebar_control(ui, "minimize", false, maximized).clicked() { ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true)); }
                });
            });
            ui.add_space(12.0 + (1.0 - reveal) * 8.0);
            ui.horizontal_top(|ui| {
                let panel_height = (ui.available_height() - 16.0).max(0.0);
                ui.add_space(12.0);
                egui::Frame::new().fill(egui::Color32::from_rgba_unmultiplied(19, 13, 27, 218)).stroke(egui::Stroke::new(1.0_f32, egui::Color32::from_rgba_unmultiplied(155, 115, 190, 26))).corner_radius(24).inner_margin(egui::Margin::same(18)).show(ui, |ui| {
                    ui.vertical(|ui| {
                        ui.set_min_width(194.0); ui.set_max_width(194.0); ui.set_min_height((panel_height - 36.0).max(0.0));
                        ui.add_space(12.0);
                        if animated_button(ui, phrase(language, "New Downgrade", "Yeni Sürüm Düşürme"), [158.0, 40.0], egui::Color32::from_rgb(76, 57, 91), true).clicked() {
                            self.input.clear(); self.output.clear(); self.details_en.clear(); self.details_tr.clear();
                            self.set_status("Choose an After Effects project to get started.", "Başlamak için bir After Effects projesi seçin.", false);
                        }
                        ui.add_space(24.0);
                        label(ui, phrase(language, "WORKSPACE", "ÇALIŞMA ALANI")); ui.add_space(8.0);
                        let single = self.mode == Mode::Single;
                        if animated_button(ui, phrase(language, "Single project", "Tek proje"), [158.0, 38.0], egui::Color32::from_rgb(76, 57, 91), single).clicked() {
                            self.mode = Mode::Single; self.input.clear(); self.output.clear(); self.details_en.clear(); self.details_tr.clear();
                        }
                        ui.add_space(4.0);
                        if animated_button(ui, phrase(language, "Batch folder", "Toplu klasör"), [158.0, 38.0], egui::Color32::from_rgb(76, 57, 91), !single).clicked() {
                            self.mode = Mode::Batch; self.input.clear(); self.output.clear(); self.details_en.clear(); self.details_tr.clear();
                        }
                        ui.add_space(20.0); ui.separator(); ui.add_space(17.0);
                        label(ui, phrase(language, "QUICK TOOLS", "HIZLI ARAÇLAR")); ui.add_space(8.0);
                        if animated_button(ui, phrase(language, "Analyze project", "Projeyi analiz et"), [158.0, 38.0], PANEL2, false).clicked() { self.inspect(); }
                        ui.add_space(16.0);
                        egui::Frame::new().fill(egui::Color32::from_rgba_unmultiplied(28, 24, 38, 170)).corner_radius(16).inner_margin(egui::Margin::symmetric(12, 10)).show(ui, |ui| {
                            ui.label(egui::RichText::new(phrase(language, "Original file stays safe", "Orijinal dosya korunur")).size(11.5).strong().color(egui::Color32::WHITE));
                            ui.add_space(3.0);
                            ui.label(egui::RichText::new(phrase(language, "A separate copy is created; your source remains unchanged.", "Ayrı bir kopya oluşturulur; kaynak dosyanız değişmeden kalır.")).size(10.0).color(MUTED));
                        });
                    });
                });
                ui.add_space(12.0);
                let workspace_width = (ui.available_width() - 15.0).max(0.0);
                ui.allocate_ui_with_layout(egui::vec2(workspace_width, ui.available_height()), egui::Layout::top_down(egui::Align::Min), |ui| {
                    egui::Frame::new().fill(egui::Color32::from_rgba_unmultiplied(23, 16, 31, 198)).stroke(egui::Stroke::new(1.0_f32, egui::Color32::from_rgba_unmultiplied(177, 125, 208, 42))).corner_radius(24).inner_margin(egui::Margin::symmetric(28, 20)).show(ui, |ui| {
                    ui.vertical(|ui| {
                        ui.set_min_width((ui.available_width() - 12.0).max(0.0));
                        ui.set_min_height((panel_height - 40.0).max(0.0));
                        ui.set_max_height((panel_height - 40.0).max(0.0));
                        egui::ScrollArea::vertical().scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden).auto_shrink([false, false]).show(ui, |ui| {
                            ui.horizontal(|ui| {
                                egui::Frame::new().fill(egui::Color32::from_rgb(34, 26, 43)).corner_radius(18).inner_margin(egui::Margin::symmetric(12, 7)).show(ui, |ui| {
                                    ui.label(egui::RichText::new(phrase(language, "AE PROJECT  /  VERSION PREP", "AE PROJESİ  /  SÜRÜM HAZIRLIĞI")).size(10.0).color(egui::Color32::from_rgb(220, 201, 241)));
                                });
                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    if animated_button(ui, phrase(language, "Türkçe", "English"), [88.0, 30.0], ACCENT, false).clicked() { toggle_language = true; }
                                });
                            });
                            ui.add_space(18.0);
                            ui.vertical_centered(|ui| {
                                let (orb_rect, _) = ui.allocate_exact_size(egui::vec2(66.0, 66.0), egui::Sense::hover());
                                let center = orb_rect.center();
                                ui.painter().circle_filled(center, 29.0, egui::Color32::from_rgba_unmultiplied(144, 57, 201, 18));
                                ui.painter().circle_filled(center, 22.0, egui::Color32::from_rgb(57, 29, 88));
                                ui.painter().circle_filled(center, 17.0, egui::Color32::from_rgb(100, 49, 151));
                                ui.painter().circle_filled(center + egui::vec2(-5.0, -7.0), 8.0, egui::Color32::from_rgb(209, 160, 245));
                                ui.label(egui::RichText::new(phrase(language, "Ready to prepare your project?", "Projenizi hazırlamaya hazır mısınız?")).size(25.0).color(egui::Color32::from_rgb(244, 236, 249)));
                                ui.add_space(4.0);
                                ui.label(egui::RichText::new(phrase(language, "Choose a project, pick an older version, and create a copy.", "Bir proje seçin, hedef sürümü belirleyin ve yeni bir kopya oluşturun.")).size(12.0).color(MUTED));
                            });
                            ui.add_space(16.0);
                            ui.horizontal(|ui| {
                                let single = self.mode == Mode::Single;
                                if animated_button(ui, phrase(language, "Single project", "Tek proje"), [126.0, 34.0], ACCENT, single).clicked() { self.mode = Mode::Single; }
                                ui.add_space(7.0);
                                if animated_button(ui, phrase(language, "Batch folder", "Toplu klasör"), [120.0, 34.0], ACCENT, !single).clicked() { self.mode = Mode::Batch; }
                                ui.add_space(7.0);
                                if animated_button(ui, phrase(language, "Analyze", "Analiz et"), [92.0, 34.0], PANEL2, false).clicked() { self.inspect(); }
                            });
                            ui.add_space(12.0);
                            egui::Frame::new().fill(egui::Color32::from_rgba_unmultiplied(31, 23, 39, 226)).stroke(egui::Stroke::new(1.0_f32, egui::Color32::from_rgb(126, 81, 153))).corner_radius(22).inner_margin(egui::Margin::same(16)).show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.label(egui::RichText::new("✦").size(17.0).color(ACCENT));
                                    ui.label(egui::RichText::new(phrase(language, "Project setup", "Proje ayarları")).size(15.0).strong().color(egui::Color32::WHITE));
                                });
                                ui.add_space(12.0);
                                let input_label = if self.mode == Mode::Single { phrase(language, "SOURCE PROJECT", "KAYNAK PROJE") } else { phrase(language, "SOURCE FOLDER", "KAYNAK KLASÖR") };
                                let input_hint = if self.mode == Mode::Single { phrase(language, "Choose an .aep project file", ".aep proje dosyası seçin") } else { phrase(language, "Choose a folder containing .aep files", ".aep dosyalarının bulunduğu klasörü seçin") };
                                if field_row(ui, input_label, &mut self.input, phrase(language, "Browse…", "Göz at…"), input_hint) { self.pick_input(); }
                                if !self.details_text().is_empty() {
                                    ui.add_space(6.0);
                                    ui.label(egui::RichText::new(format!("●  {}", self.details_text())).size(11.0).color(if self.kind { egui::Color32::from_rgb(255, 133, 132) } else { egui::Color32::from_rgb(109, 213, 166) }));
                                }
                                ui.add_space(13.0);
                                let output_label = if self.mode == Mode::Single { phrase(language, "SAVE COPY AS", "KOPYAYI ŞURAYA KAYDET") } else { phrase(language, "OUTPUT FOLDER", "ÇIKTI KLASÖRÜ") };
                                let output_hint = if self.mode == Mode::Single { phrase(language, "A separate output file keeps your original safe", "Ayrı çıktı dosyası orijinalinizi korur") } else { phrase(language, "Choose a destination folder", "Çıktı klasörünü seçin") };
                                if field_row(ui, output_label, &mut self.output, phrase(language, "Browse…", "Göz at…"), output_hint) { self.pick_output(); }
                                ui.add_space(16.0);
                                ui.horizontal(|ui| {
                                    ui.vertical(|ui| {
                                        label(ui, phrase(language, "TARGET VERSION", "HEDEF SÜRÜM")); ui.add_space(6.0);
                                        egui::ComboBox::from_id_salt("target_version").selected_text(format!("After Effects {}", self.year)).width(190.0).show_ui(ui, |ui| {
                                            for (year, _) in VERSIONS { ui.selectable_value(&mut self.year, *year, format!("After Effects {year}")); }
                                        });
                                    });
                                    ui.add_space(20.0);
                                    ui.vertical(|ui| {
                                        label(ui, phrase(language, "OPTIONS", "SEÇENEKLER")); ui.add_space(3.0);
                                        ui.checkbox(&mut self.dry_run, phrase(language, "Preview only", "Yalnızca önizle"));
                                        ui.checkbox(&mut self.force, phrase(language, "Force version update", "Sürümü zorla değiştir"));
                                    });
                                });
                                ui.add_space(16.0);
                                ui.horizontal(|ui| {
                                    let button_text = if self.dry_run { phrase(language, "Preview downgrade", "Düşürmeyi önizle") } else if self.mode == Mode::Single { phrase(language, "Downgrade project", "Sürümü düşür") } else { phrase(language, "Process folder", "Klasörü işle") };
                                    if animated_button(ui, &format!("↑   {button_text}"), [205.0, 44.0], ACCENT, true).clicked() { self.process(); }
                                    ui.add_space(12.0);
                                    ui.vertical(|ui| {
                                        ui.label(egui::RichText::new(if self.kind { phrase(language, "! ERROR", "! HATA") } else { phrase(language, "STATUS", "DURUM") }).size(9.0).strong().color(if self.kind { egui::Color32::from_rgb(255, 171, 100) } else { MUTED }));
                                        ui.label(egui::RichText::new(self.status_text()).size(11.0).color(egui::Color32::from_rgb(225, 218, 232)));
                                    });
                                });
                            });
                            ui.add_space(15.0);
                            ui.columns(3, |columns| {
                                let cards = [
                                    (phrase(language, "Project details", "Proje bilgisi"), phrase(language, "Inspect the project version and file header.", "Proje sürümünü ve dosya başlığını inceleyin.")),
                                    (phrase(language, "Safe copy", "Güvenli kopya"), phrase(language, "Keep your source file and save a new copy.", "Kaynak dosyayı koruyup yeni bir kopya kaydedin.")),
                                    (phrase(language, "Batch workflow", "Toplu işlem"), phrase(language, "Prepare multiple projects from one folder.", "Bir klasördeki birden fazla projeyi hazırlayın.")),
                                ];
                                for (column, (title, body)) in columns.iter_mut().zip(cards) {
                                    egui::Frame::new().fill(egui::Color32::from_rgba_unmultiplied(18, 14, 25, 220)).stroke(egui::Stroke::new(1.0_f32, egui::Color32::from_rgba_unmultiplied(130, 103, 153, 26))).corner_radius(22).inner_margin(egui::Margin::same(17)).show(column, |ui| {
                                        ui.label(egui::RichText::new(title).size(11.0).strong().color(egui::Color32::WHITE));
                                        ui.label(egui::RichText::new(body).size(9.5).color(MUTED));
                                    });
                                }
                            });
                        });
                    });
                });
                    });
            });
            if reveal < 0.999 {
                let alpha = ((1.0 - reveal) * 235.0).clamp(0.0, 235.0) as u8;
                let intro = ctx.layer_painter(egui::LayerId::new(egui::Order::Foreground, egui::Id::new("intro_fade")))
                    .with_clip_rect(ctx.screen_rect());
                intro.rect_filled(ctx.screen_rect(), 22, egui::Color32::from_rgba_unmultiplied(16, 10, 24, alpha));
                ctx.request_repaint();
            }        });
        if toggle_language {
            self.language = match self.language { Language::English => Language::Turkish, Language::Turkish => Language::English };
        }
    }
}
fn launch_gui() -> Result<(), String> {
    let icon_image = image::load_from_memory(include_bytes!("../assets/icon.ico")).expect("Invalid application icon").into_rgba8();
    let (icon_width, icon_height) = icon_image.dimensions();
    let icon = egui::IconData { rgba: icon_image.into_raw(), width: icon_width, height: icon_height };
    let options = eframe::NativeOptions { viewport: egui::ViewportBuilder::default().with_title("AE Project Downgrader").with_inner_size([1280.0, 820.0]).with_min_inner_size([760.0, 560.0]).with_decorations(false).with_transparent(false).with_icon(Arc::new(icon)), ..Default::default() };
    eframe::run_native("AE Project Downgrader", options, Box::new(|cc| {
        #[cfg(target_os = "windows")]
        unsafe {
            use raw_window_handle::{HasWindowHandle as _, RawWindowHandle};
            use windows_sys::Win32::Graphics::Dwm::{DwmSetWindowAttribute, DWMWA_WINDOW_CORNER_PREFERENCE, DWMWA_BORDER_COLOR, DWMWA_COLOR_NONE};
            if let Ok(window_handle) = cc.window_handle() {
                if let RawWindowHandle::Win32(handle) = window_handle.as_raw() {
                    let preference = 2u32;
                    let hwnd = handle.hwnd.get() as _;
                    let _ = DwmSetWindowAttribute(hwnd, DWMWA_WINDOW_CORNER_PREFERENCE as u32, &preference as *const u32 as *const core::ffi::c_void, std::mem::size_of::<u32>() as u32);
                    let _ = DwmSetWindowAttribute(hwnd, DWMWA_BORDER_COLOR as u32, &DWMWA_COLOR_NONE as *const u32 as *const core::ffi::c_void, std::mem::size_of::<u32>() as u32);
                }
            }
        }
        let mut fonts = egui::FontDefinitions::default();
        if let Some(windows_dir) = std::env::var_os("WINDIR") {
            let fonts_dir = PathBuf::from(windows_dir).join("Fonts");
            let font_bytes = fs::read(fonts_dir.join("SegUIVar.ttf"))
                .or_else(|_| fs::read(fonts_dir.join("segoeui.ttf")));
            if let Ok(bytes) = font_bytes {
                fonts.font_data.insert("Segoe UI".to_owned(), Arc::new(egui::FontData::from_owned(bytes)));
                fonts.families.entry(egui::FontFamily::Proportional).or_default().insert(0, "Segoe UI".to_owned());
                cc.egui_ctx.set_fonts(fonts);
            }
        }
        Ok(Box::<DowngraderApp>::default())
    }))
        .map_err(|e| format!("Could not start desktop interface: {e}"))
}
fn main() {
    if env::args_os().len() == 1 {
        if let Err(error) = launch_gui() { safe_eprintln!("Error: {error}"); process::exit(1); }
        return;
    }
    if let Err(error) = run() { safe_eprintln!("Error: {error}"); process::exit(1); }
}























