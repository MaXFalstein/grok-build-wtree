# Homebrew formula for groktree.
#
# From crates.io:
#   cargo install groktree
#
# From this git repository:
#   cargo install --git https://github.com/MaXFalstein/grok-build-wtree --locked
#
# For a tap, point `url` at a release tarball and fill in `sha256`, or:
#   brew install --HEAD ./packaging/homebrew/groktree.rb
class Groktree < Formula
  desc "Read-only inspector for Grok Build worktrees, origins, and git repos"
  homepage "https://github.com/MaXFalstein/grok-build-wtree"
  license "MIT"
  version "0.1.0"
  head "https://github.com/MaXFalstein/grok-build-wtree.git", branch: "main"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args
  end

  test do
    assert_match "groktree", shell_output("#{bin}/groktree --version")
  end
end
