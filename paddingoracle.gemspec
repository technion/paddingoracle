# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'paddingoracle/version'

Gem::Specification.new do |spec|
  spec.name          = "paddingoracle"
  spec.version       = Paddingoracle::VERSION
  spec.authors       = ["Technion"]
  spec.email         = ["technion@lolware.net"]

  spec.summary       = %q{A padding oracle exploit kit.}
  spec.description   = %q{A framework for creating custom padding oracle exploits.}
  spec.homepage      = "https://github.com/technion/paddingoracle"
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.13"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "minitest", "~> 5.0"
  spec.add_development_dependency "httparty"
end
