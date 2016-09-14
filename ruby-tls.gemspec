# frozen_string_literal: true
# -*- encoding: utf-8 -*-

$:.push File.expand_path("../lib", __FILE__)
require "ruby-tls/version"

Gem::Specification.new do |s|
    s.name        = "ruby-tls"
    s.version     = RubyTls::VERSION
    s.authors     = ["Stephen von Takach"]
    s.email       = ["steve@cotag.me"]
    s.licenses    = ["MIT"]
    s.homepage    = "https://github.com/cotag/ruby-tls"
    s.summary     = "Abstract TLS for Ruby"
    s.description = <<-EOF
        Allows transport layers outside Ruby TCP to be secured.
    EOF


    s.add_dependency 'ffi-compiler',    '>= 1.0', '< 2.0'
    s.add_dependency 'concurrent-ruby', '~> 1.0'

    s.add_development_dependency 'rspec', '~> 3.5'
    s.add_development_dependency 'yard',  '~> 0.9'


    s.files = Dir["{lib}/**/*"] + %w(ruby-tls.gemspec README.md)
    s.test_files = Dir["spec/**/*"]
    s.extra_rdoc_files = ["README.md"]

    s.require_paths = ["lib"]
end
