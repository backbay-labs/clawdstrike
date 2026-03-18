# Homebrew formula for hush CLI
# Install: brew install clawdstrike/tap/hush
# Or from local: brew install --build-from-source ./infra/packaging/HomebrewFormula/hush.rb
#
# SHA256 is automatically updated by the release workflow.
# To calculate SHA256 manually:
#   curl -sL https://github.com/backbay-labs/clawdstrike/archive/refs/tags/vX.Y.Z.tar.gz | shasum -a 256

class Hush < Formula
  desc "CLI for clawdstrike security verification and policy enforcement"
  homepage "https://github.com/backbay-labs/clawdstrike"
  url "https://github.com/backbay-labs/clawdstrike/archive/refs/tags/v0.2.7.tar.gz"
  sha256 "PLACEHOLDER_SHA256_WILL_BE_UPDATED_ON_RELEASE"
  license "Apache-2.0"
  head "https://github.com/backbay-labs/clawdstrike.git", branch: "main"

  depends_on "rust" => :build
  depends_on "bun"

  def install
    system "cargo", "install", *std_cargo_args(path: "crates/services/hush-cli")
    system "cargo", "install", *std_cargo_args(path: "crates/services/hushd")

    tui_dir = share/"clawdstrike/tui"
    tui_dir.mkpath
    tui_dir.install "apps/terminal/package.json"
    tui_dir.install "apps/terminal/bun.lockb"
    tui_dir.install "crates/services/hush-cli/assets/tui/cli.js"
    cp_r "apps/terminal/src", tui_dir/"src"
    cd tui_dir do
      system "bun", "install", "--production", "--frozen-lockfile"
    end

    # Generate shell completions
    generate_completions_from_executable(bin/"hush", "completions")
  end

  test do
    assert_match "hush #{version}", shell_output("#{bin}/hush --version")
    assert_match "hushd", shell_output("#{bin}/hushd --version")

    # Test basic help
    assert_match "security verification", shell_output("#{bin}/hush --help")
    assert_match "\"runtime\"", shell_output("#{bin}/clawdstrike tui doctor --json")
  end
end
