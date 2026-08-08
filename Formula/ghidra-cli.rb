# Homebrew formula for ghidra-cli (in-repo; not yet submitted upstream).
# Install from this repo:
#   brew install --build-from-source ./Formula/ghidra-cli.rb
# Or create a tap that points at this formula.

class GhidraCli < Formula
  desc "Rust CLI for Ghidra headless reverse engineering and native MCP tools"
  homepage "https://github.com/akiselev/ghidra-cli"
  url "https://github.com/akiselev/ghidra-cli.git", tag: "v0.2.1"
  license "GPL-3.0-only"
  head "https://github.com/akiselev/ghidra-cli.git", branch: "master"

  depends_on "rust" => :build
  # Runtime: Ghidra + full JDK 21+ (install separately or via `ghidra setup`)
  depends_on "openjdk" => :recommended

  def install
    system "cargo", "install", *std_cargo_args
  end

  def caveats
    <<~EOS
      ghidra-cli needs a Ghidra install and a full JDK 21+.

        ghidra doctor          # diagnose install
        ghidra setup          # download/install Ghidra if missing
        ghidra mcp stdio      # native MCP for agents
        ghidra mcp http --listen 127.0.0.1:0

      See docs/MCP.md and skills/triage-decomp-patch-export.md.
    EOS
  end

  test do
    assert_match "ghidra", shell_output("#{bin}/ghidra --help")
    assert_match "mcp", shell_output("#{bin}/ghidra mcp --help")
  end
end
