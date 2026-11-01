# Homebrew formula for groktree.
#
# From crates.io:
#   cargo install groktree
#
# From this git repository:
#   cargo install --git https://github.com/MaXFalstein/grok-build-wtree --locked
#
# Stable install from the tap:
#   brew install maxfalstein/groktree/groktree
class Groktree < Formula
  desc "Read-only inspector for Grok Build worktrees, origins, and git repos"
  homepage "https://github.com/MaXFalstein/grok-build-wtree"
  url "https://github.com/MaXFalstein/grok-build-wtree/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "09cde2c72626426951543f97e6bd8850fe83a3372cd399539f2226cf52fc8a9a"
  license any_of: ["MIT", "Apache-2.0"]
  head "https://github.com/MaXFalstein/grok-build-wtree.git", branch: "main"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args
  end

  test do
    (testpath/"note.txt").write("hello\n")
    require "json"
    output = shell_output("#{bin}/groktree stats --json \"#{testpath}\"")
    stats = JSON.parse(output)
    assert_equal 1, stats["paths"].fetch(0)["files"]
  end
end
