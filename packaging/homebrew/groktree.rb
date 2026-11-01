# Homebrew formula for groktree.
#
# From crates.io:
#   cargo install groktree
#
# From this git repository:
#   cargo install --git https://github.com/MaXFalstein/groktree --locked
#
# Stable install from the tap:
#   brew install maxfalstein/groktree/groktree
class Groktree < Formula
  desc "Read-only inspector for Grok Build worktrees, origins, and git repos"
  homepage "https://github.com/MaXFalstein/groktree"
  url "https://github.com/MaXFalstein/groktree/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "110c4d76aadc73b5be7de09e48fc1f0150a797b9d0ad7795ec10ffc4e5470faf"
  license any_of: ["MIT", "Apache-2.0"]
  head "https://github.com/MaXFalstein/groktree.git", branch: "main"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args
  end

  test do
    # Homebrew writes .gitconfig and .bazelrc into testpath before the block.
    # Scan a child directory so the count is only the file this test writes.
    (testpath/"sample").mkpath
    (testpath/"sample/note.txt").write("hello\n")
    require "json"
    output = shell_output("#{bin}/groktree stats --json \"#{testpath}/sample\"")
    stats = JSON.parse(output)
    assert_equal 1, stats["paths"].fetch(0)["files"]
  end
end
