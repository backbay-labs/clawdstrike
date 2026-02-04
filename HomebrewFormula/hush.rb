# Homebrew formula for hush CLI
# Install: brew install clawdstrike/tap/hush
# Or from local: brew install --build-from-source ./HomebrewFormula/hush.rb
#
# SHA256 is automatically updated by the release workflow.
# To calculate SHA256 manually:
#   curl -sL https://github.com/backbay-labs/clawdstrike/archive/refs/tags/vX.Y.Z.tar.gz | shasum -a 256

class Hush < Formula
  desc "CLI for clawdstrike security verification and policy enforcement"
  homepage "https://github.com/backbay-labs/clawdstrike"
  url "https://github.com/backbay-labs/clawdstrike/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "PLACEHOLDER_SHA256_WILL_BE_UPDATED_ON_RELEASE"
  license "MIT"
  head "https://github.com/backbay-labs/clawdstrike.git", branch: "main"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args(path: "crates/hush-cli")

    # Generate shell completions
    generate_completions_from_executable(bin/"hush", "completions")
  end

  def caveats
    <<~EOS
      This formula installs the `hush` CLI only.

      The `hushd` daemon is experimental and is not installed by default.
      If you want to try it anyway, build it from source:

        cargo install --path crates/hushd
    EOS
  end

  test do
    assert_match "hush #{version}", shell_output("#{bin}/hush --version")

    # Test basic help
    assert_match "security verification", shell_output("#{bin}/hush --help")
  end
end
