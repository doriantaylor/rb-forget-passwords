# -*- mode: enh-ruby -*-
lib = File.expand_path("../lib", __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'forget-passwords/version'

Gem::Specification.new do |spec|
  spec.name        = "forget-passwords"
  spec.version     = ForgetPasswords::VERSION
  spec.authors     = ["Dorian Taylor"]
  spec.email       = ["code@doriantaylor.com"]
  spec.license     = 'Apache-2.0'
  spec.homepage    = 'https://github.com/doriantaylor/rb-forget-passwords'
  spec.summary     = 'Web authentication module for the extremely lazy'
  spec.description = <<-DESC
This little module (and attendant command line tool and rackup app)
exists for the purpose of providing rudimentary access control to a
website when the prospective users are both small in number, and very
busy. It circumvents schmucking around provisioning passwords by
generating a link which you can pass to each of your users through
some other mechanism, that when visited logs them in and keeps them
logged in as long as you want. This is basically the equivalent of
having a "forgot password" link without anybody having to click on
"forgot password", and is perfectly adequate security in certain
contexts, namely the ones the author of this gem is interested in.
DESC

  # switch based on whether we're a git or hg repository
  wd = File.dirname lib
  spec.files = if File.exist?("#{wd}/.git")
                 `git ls-files -z`
               elsif File.exist?("#{wd}/.hg")
                 `hg files -0`
               else
                 raise "Can't find a git or hg repository!"
               end.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end

  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  # ruby
  spec.required_ruby_version = '>= 2'

  # dev/test dependencies
  spec.add_development_dependency 'bundler', '>= 2.1'
  spec.add_development_dependency 'rake',    '>= 13.0'
  spec.add_development_dependency 'rspec',   '>= 3.9'

  # stuff we use
  spec.add_runtime_dependency 'commander',  '>= 4.4'
  spec.add_runtime_dependency 'deep_merge', '>= 1.2'
  spec.add_runtime_dependency 'dry-schema', '>= 1.9.1'
  spec.add_runtime_dependency 'dry-types',  '>= 1.5.1'
  spec.add_runtime_dependency 'fcgi',       '>= 0.9.2.1'
  spec.add_runtime_dependency 'iso8601',    '>= 0.12'
  spec.add_runtime_dependency 'mail',       '>= 2.7.1'
  spec.add_runtime_dependency 'rack',       '~> 2' # rack 3 breaks stuff
  spec.add_runtime_dependency 'sequel',     '>= 5.20'
  spec.add_runtime_dependency 'uuidtools',  '>= 2.1'

  # stuff i wrote
  spec.add_runtime_dependency 'http-negotiate', '>= 0.1.3'
  spec.add_runtime_dependency 'uuid-ncname',    '>= 0.2'
  spec.add_runtime_dependency 'xml-mixup',      '>= 0.1.13'
end
