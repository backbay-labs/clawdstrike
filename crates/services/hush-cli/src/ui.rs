use std::io::Write;

use colored::Colorize;
use comfy_table::{presets::UTF8_FULL, ContentArrangement, Table};
use indicatif::{ProgressBar, ProgressStyle};

/// Initialize color support. Disables color when `--no-color` flag is set
/// or `NO_COLOR` environment variable is present.
pub fn init_color(no_color: bool) {
    if no_color || std::env::var_os("NO_COLOR").is_some() {
        colored::control::set_override(false);
    }
}

/// Get terminal width, defaulting to 80.
pub fn term_width() -> usize {
    console::Term::stdout()
        .size_checked()
        .map(|(_, w)| w as usize)
        .unwrap_or(80)
}

/// Verdict types for CLI output badges.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Allowed,
    Blocked,
    Warn,
    Error,
    Valid,
    Invalid,
    Pass,
    Fail,
}

impl Verdict {
    /// Render a colored badge string for this verdict.
    pub fn badge(self) -> String {
        match self {
            Self::Allowed => format!(" {} ", "✓ ALLOWED".green().bold()),
            Self::Blocked => format!(" {} ", "✗ BLOCKED".red().bold()),
            Self::Warn => format!(" {} ", "⚠ WARN".yellow().bold()),
            Self::Error => format!(" {} ", "✗ ERROR".red().bold()),
            Self::Valid => format!(" {} ", "✓ VALID".green().bold()),
            Self::Invalid => format!(" {} ", "✗ INVALID".red().bold()),
            Self::Pass => format!(" {} ", "✓ PASS".green().bold()),
            Self::Fail => format!(" {} ", "✗ FAIL".red().bold()),
        }
    }

    /// Render the verdict icon only (✓ or ✗ or ⚠).
    pub fn icon(self) -> String {
        match self {
            Self::Allowed | Self::Valid | Self::Pass => "✓".green().to_string(),
            Self::Blocked | Self::Invalid | Self::Fail | Self::Error => "✗".red().to_string(),
            Self::Warn => "⚠".yellow().to_string(),
        }
    }
}

/// Render a Unicode box with a title and body lines.
///
/// Lines and titles that exceed the inner width are truncated with `…`.
/// Terminal widths below 20 are clamped to 20 to avoid degenerate output.
pub fn render_box(title: &str, lines: &[String], out: &mut dyn Write) {
    let width = term_width().clamp(20, 100);
    let inner_width = width.saturating_sub(4); // account for "│ " and " │"

    let top_bar = "─".repeat(inner_width + 2);
    let _ = writeln!(out, "┌{}┐", top_bar);

    // Truncate title if it exceeds inner_width
    let truncated_title = truncate_to_width(title, inner_width);
    let title_plain_len = console::measure_text_width(&truncated_title);
    let padding = inner_width.saturating_sub(title_plain_len);
    let _ = writeln!(out, "│ {}{} │", truncated_title.bold(), " ".repeat(padding));

    let separator = "─".repeat(inner_width + 2);
    let _ = writeln!(out, "├{}┤", separator);

    for line in lines {
        let stripped_len = console::measure_text_width(line);
        if stripped_len <= inner_width {
            let pad = inner_width - stripped_len;
            let _ = writeln!(out, "│ {}{} │", line, " ".repeat(pad));
        } else {
            // Truncate overlong lines to keep the box intact
            let truncated = truncate_to_width(line, inner_width);
            let tlen = console::measure_text_width(&truncated);
            let pad = inner_width.saturating_sub(tlen);
            let _ = writeln!(out, "│ {}{} │", truncated, " ".repeat(pad));
        }
    }

    let bottom_bar = "─".repeat(inner_width + 2);
    let _ = writeln!(out, "└{}┘", bottom_bar);
}

/// Truncate a string (by display width) to fit within `max_width`,
/// appending `…` if truncation occurs. Accounts for wide characters
/// (CJK, emoji) that occupy 2 terminal columns.
fn truncate_to_width(s: &str, max_width: usize) -> String {
    let visible_width = console::measure_text_width(s);
    if visible_width <= max_width {
        return s.to_string();
    }
    if max_width == 0 {
        return String::new();
    }
    // Strip ANSI codes first, then truncate by display width (not char count).
    let stripped = console::strip_ansi_codes(s);
    let target = max_width.saturating_sub(1); // reserve 1 column for `…`
    let mut width = 0;
    let mut truncated = String::new();
    for ch in stripped.chars() {
        let ch_width = unicode_width::UnicodeWidthChar::width(ch).unwrap_or(0);
        if width + ch_width > target {
            break;
        }
        width += ch_width;
        truncated.push(ch);
    }
    truncated.push('…');
    truncated
}

/// Print a bold underlined section header.
pub fn section(label: &str, out: &mut dyn Write) {
    let _ = writeln!(out, "\n{}", label.bold().underline());
}

/// Print a dimmed key: value pair.
pub fn kv(key: &str, value: &str, out: &mut dyn Write) {
    let _ = writeln!(out, "  {} {}", format!("{}:", key).dimmed(), value);
}

/// Print a guard result row with icon.
pub fn guard_row(allowed: bool, guard: &str, message: &str, out: &mut dyn Write) {
    let icon = if allowed {
        "✓".green().to_string()
    } else {
        "✗".red().to_string()
    };
    let _ = writeln!(out, "  {} {} {}", icon, guard.bold(), message.dimmed());
}

/// Render the ASCII art banner.
pub fn banner(out: &mut dyn Write) {
    let art = r#"
   _____ _                     _     _        _ _
  / ____| |                   | |   | |      (_) |
 | |    | | __ ___      _____ | |___| |_ _ __ _| | _____
 | |    | |/ _` \ \ /\ / / _ \| / __| __| '__| | |/ / _ \
 | |____| | (_| |\ V  V / (_) | \__ \ |_| |  | |   <  __/
  \_____|_|\__,_| \_/\_/ \___/|_|___/\__|_|  |_|_|\_\___|"#;
    let _ = writeln!(out, "{}", art.cyan().bold());
}

/// Render the version banner (banner + version string).
pub fn version_banner(out: &mut dyn Write) {
    banner(out);
    let _ = writeln!(
        out,
        "  {}",
        format!("v{}", env!("CARGO_PKG_VERSION")).dimmed()
    );
    let _ = writeln!(out);
}

/// Create a pre-configured comfy-table with UTF-8 borders and dynamic width.
pub fn new_table(headers: &[&str]) -> Table {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_width(term_width().min(u16::MAX as usize) as u16);
    table.set_header(headers);
    table
}

/// Create an indicatif spinner (writes to stderr so it won't interfere with JSON on stdout).
pub fn spinner(message: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::with_template("{spinner:.cyan} {msg}")
            .unwrap_or_else(|_| ProgressStyle::default_spinner()),
    );
    pb.set_message(message.to_string());
    pb.enable_steady_tick(std::time::Duration::from_millis(80));
    pb
}

/// Render a colored count string like "3 passed".
pub fn count_pass(n: u64) -> String {
    if n > 0 {
        format!("{} passed", n).green().to_string()
    } else {
        format!("{} passed", n).to_string()
    }
}

/// Render a colored count string like "1 failed".
pub fn count_fail(n: u64) -> String {
    if n > 0 {
        format!("{} failed", n).red().to_string()
    } else {
        format!("{} failed", n).to_string()
    }
}

/// Render a colored count string like "2 warnings".
pub fn count_warn(n: u64) -> String {
    let label = if n == 1 { "warning" } else { "warnings" };
    if n > 0 {
        format!("{} {}", n, label).yellow().to_string()
    } else {
        format!("{} {}", n, label).to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() {
        colored::control::set_override(false);
    }

    /// Render a rustc-style YAML diagnostic with line numbers and caret.
    /// Only used in tests; available for future production use if needed.
    fn yaml_diagnostic(source: &str, err_msg: &str, out: &mut dyn Write) {
        let _ = writeln!(out, "{}: {}", "error".red().bold(), err_msg.bold());

        let (line, col) = parse_yaml_line_col(err_msg);

        if let Some(line_num) = line {
            let lines: Vec<&str> = source.lines().collect();
            let gutter_width = format!("{}", line_num + 1).len();

            let start = line_num.saturating_sub(2);
            let end = (line_num + 3).min(lines.len());

            let _ = writeln!(
                out,
                "{}",
                format!("{:>width$} │", "", width = gutter_width).dimmed()
            );

            for i in start..end {
                if i < lines.len() {
                    let num = i + 1;
                    if i == line_num {
                        let _ = writeln!(
                            out,
                            "{} {}",
                            format!("{:>width$} │", num, width = gutter_width)
                                .blue()
                                .bold(),
                            lines[i]
                        );
                        if let Some(c) = col {
                            let _ = writeln!(
                                out,
                                "{} {}{}",
                                format!("{:>width$} │", "", width = gutter_width).dimmed(),
                                " ".repeat(c.saturating_sub(1)),
                                "^".red().bold()
                            );
                        }
                    } else {
                        let _ = writeln!(
                            out,
                            "{} {}",
                            format!("{:>width$} │", num, width = gutter_width).dimmed(),
                            lines[i]
                        );
                    }
                }
            }
        }
    }

    fn parse_yaml_line_col(msg: &str) -> (Option<usize>, Option<usize>) {
        let mut line = None;
        let mut col = None;

        if let Some(idx) = msg.find("at line ") {
            let rest = &msg[idx + 8..];
            let num_str: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            if let Ok(n) = num_str.parse::<usize>() {
                line = Some(n.saturating_sub(1));
            }
            if let Some(col_idx) = rest.find("column ") {
                let col_rest = &rest[col_idx + 7..];
                let col_str: String = col_rest
                    .chars()
                    .take_while(|c| c.is_ascii_digit())
                    .collect();
                if let Ok(c) = col_str.parse::<usize>() {
                    col = Some(c);
                }
            }
        }

        (line, col)
    }

    #[test]
    fn verdict_badge_no_color() {
        setup();
        assert!(Verdict::Allowed.badge().contains("ALLOWED"));
        assert!(Verdict::Blocked.badge().contains("BLOCKED"));
        assert!(Verdict::Warn.badge().contains("WARN"));
        assert!(Verdict::Error.badge().contains("ERROR"));
        assert!(Verdict::Valid.badge().contains("VALID"));
        assert!(Verdict::Invalid.badge().contains("INVALID"));
        assert!(Verdict::Pass.badge().contains("PASS"));
        assert!(Verdict::Fail.badge().contains("FAIL"));
    }

    #[test]
    fn verdict_icon_no_color() {
        setup();
        assert_eq!(Verdict::Allowed.icon(), "✓");
        assert_eq!(Verdict::Valid.icon(), "✓");
        assert_eq!(Verdict::Pass.icon(), "✓");
        assert_eq!(Verdict::Blocked.icon(), "✗");
        assert_eq!(Verdict::Invalid.icon(), "✗");
        assert_eq!(Verdict::Fail.icon(), "✗");
        assert_eq!(Verdict::Error.icon(), "✗");
        assert_eq!(Verdict::Warn.icon(), "⚠");
    }

    #[test]
    fn render_box_basic() {
        setup();
        let mut out = Vec::new();
        render_box(
            "Test",
            &["line one".to_string(), "line two".to_string()],
            &mut out,
        );
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("Test"));
        assert!(text.contains("line one"));
        assert!(text.contains("line two"));
        assert!(text.contains('┌'));
        assert!(text.contains('└'));
    }

    #[test]
    fn section_renders_label() {
        setup();
        let mut out = Vec::new();
        section("My Section", &mut out);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("My Section"));
    }

    #[test]
    fn kv_renders_pair() {
        setup();
        let mut out = Vec::new();
        kv("Name", "clawdstrike", &mut out);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("Name:"));
        assert!(text.contains("clawdstrike"));
    }

    #[test]
    fn guard_row_renders_icons() {
        setup();
        let mut out = Vec::new();
        guard_row(true, "forbidden_path", "allowed", &mut out);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains('✓'));
        assert!(text.contains("forbidden_path"));

        let mut out = Vec::new();
        guard_row(false, "egress", "blocked", &mut out);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains('✗'));
        assert!(text.contains("egress"));
    }

    #[test]
    fn parse_yaml_line_col_extracts_info() {
        let (line, col) = parse_yaml_line_col("something at line 5 column 3 more text");
        assert_eq!(line, Some(4)); // 0-indexed
        assert_eq!(col, Some(3));
    }

    #[test]
    fn parse_yaml_line_col_no_match() {
        let (line, col) = parse_yaml_line_col("no location info here");
        assert_eq!(line, None);
        assert_eq!(col, None);
    }

    #[test]
    fn new_table_has_headers() {
        setup();
        let table = new_table(&["Name", "Value"]);
        let rendered = table.to_string();
        assert!(rendered.contains("Name"));
        assert!(rendered.contains("Value"));
    }

    #[test]
    fn yaml_diagnostic_renders_context() {
        setup();
        let source = "line1\nline2\nbad line\nline4\nline5";
        let mut out = Vec::new();
        yaml_diagnostic(source, "problem at line 3 column 5", &mut out);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("error"));
        assert!(text.contains("bad line"));
        assert!(text.contains('^'));
    }

    #[test]
    fn render_box_empty_lines() {
        setup();
        let mut out = Vec::new();
        render_box("Empty", &[], &mut out);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("Empty"));
        assert!(text.contains('┌'));
        assert!(text.contains('└'));
    }

    #[test]
    fn render_box_long_line_truncated() {
        setup();
        let long = "x".repeat(200);
        let mut out = Vec::new();
        render_box("Title", &[long], &mut out);
        let text = String::from_utf8(out).unwrap();
        // The box should still be well-formed (closing border on every line)
        for line in text.lines() {
            if line.starts_with('│') {
                assert!(
                    line.ends_with('│'),
                    "Box line missing closing border: {}",
                    line
                );
            }
        }
        // Long content should be truncated with ellipsis
        assert!(text.contains('…'));
    }

    #[test]
    fn truncate_to_width_short_string() {
        assert_eq!(truncate_to_width("hello", 10), "hello");
    }

    #[test]
    fn truncate_to_width_exact() {
        assert_eq!(truncate_to_width("hello", 5), "hello");
    }

    #[test]
    fn truncate_to_width_long_string() {
        let result = truncate_to_width("hello world", 5);
        assert_eq!(result, "hell…");
        assert_eq!(console::measure_text_width(&result), 5);
    }

    #[test]
    fn truncate_to_width_zero() {
        assert_eq!(truncate_to_width("hello", 0), "");
    }

    #[test]
    fn truncate_to_width_wide_chars() {
        // CJK characters are 2 columns wide each
        let cjk = "你好世界测试"; // 6 chars, 12 display columns
        let result = truncate_to_width(cjk, 5);
        // Should fit 2 wide chars (4 cols) + ellipsis (1 col) = 5
        assert_eq!(console::measure_text_width(&result), 5);
        assert!(result.ends_with('…'));
    }

    #[test]
    fn banner_renders() {
        setup();
        let mut out = Vec::new();
        banner(&mut out);
        let text = String::from_utf8(out).unwrap();
        // The ASCII art splits "Clawdstrike" across lines as figlet characters,
        // so we check for a substring that appears in the bottom row.
        assert!(text.contains("___|"));
    }

    #[test]
    fn count_helpers_no_color() {
        setup();
        assert!(count_pass(3u64).contains("3 passed"));
        assert!(count_fail(1u64).contains("1 failed"));
        assert!(count_warn(0u64).contains("0 warnings"));
        assert!(count_warn(1u64).contains("1 warning"));
        assert!(!count_warn(1u64).contains("warnings"));
    }
}
