# Homebrew formula for hush CLI
# Install: brew install hushclaw/tap/hush
# Or from local: brew install --build-from-source ./HomebrewFormula/hush.rb

class Hush < Formula
  desc "CLI for hushclaw security verification and policy enforcement"
  homepage "https://github.com/hushclaw/hushclaw"
  url "https://github.com/hushclaw/hushclaw/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "PLACEHOLDER_SHA256_WILL_BE_UPDATED_ON_RELEASE"
  license "MIT"
  head "https://github.com/hushclaw/hushclaw.git", branch: "main"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args(path: "crates/hush-cli")

    # Generate shell completions
    generate_completions_from_executable(bin/"hush", "completions")
  end

  test do
    assert_match "hush #{version}", shell_output("#{bin}/hush --version")

    # Test basic help
    assert_match "security verification", shell_output("#{bin}/hush --help")
  end
end
