class CorgeaCli < Formula
  include Language::Python::Virtualenv

  desc "CLI tool for corgea"
  homepage "https://pypi.org/project/corgea-cli/"
  url "https://files.pythonhosted.org/packages/f8/29/b0c2dbf5af9e617cff850cb18e0f581baab2fded883a834c2521910a387f/corgea_cli-1.6.3.tar.gz"
  sha256 "1ff18b9c244093528a28377c15ab27f5c1d07b2e9b00912015daac634ed99009"

  depends_on "python@3.11"

  def install
    virtualenv_install_with_resources
  end

  test do
    system "#{bin}/corgea", "--help"
  end
end
