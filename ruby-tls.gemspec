# -*- encoding: utf-8 -*-
$:.push File.expand_path("../lib", __FILE__)
require "ruby-tls/version"

Gem::Specification.new do |s|
    s.name        = "ruby-tls"
    s.version     = RubyTls::VERSION
    s.authors     = ["Stephen von Takach"]
    s.email       = ["steve@cotag.me"]
    s.licenses    = ["Ruby", "GPL"]
    s.homepage    = "https://github.com/cotag/ruby-tls"
    s.summary     = "Abstract TLS for Ruby"
    s.description = <<-EOF
        Allows transport layers outside Ruby TCP be secured.
    EOF


    s.add_dependency 'ffi-compiler', '>= 0.0.2'
    s.add_dependency 'thread_safe'
    s.add_dependency 'rake'

    s.add_development_dependency 'rspec'
    s.add_development_dependency 'yard'


    s.files = Dir["{lib}/**/*"] + %w(Rakefile ruby-tls.gemspec README.md EM-LICENSE)
    s.files += ["ext/tls/ssl.cpp", "ext/tls/ssl.h", "ext/tls/page.cpp", "ext/tls/page.h"]
    s.test_files = Dir["spec/**/*"]
    s.extra_rdoc_files = ["README.md"]

    s.extensions << "ext/Rakefile"
    s.require_paths = ["lib"]
end
