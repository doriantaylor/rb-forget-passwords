# -*- mode: enh-ruby -*-
lib = File.expand_path("../lib", __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require "lazyauth/version"

Gem::Specification.new do |spec|
  spec.name        = "lazyauth"
  spec.version     = LazyAuth::VERSION
  spec.authors     = ["Dorian Taylor"]
  spec.email       = ["code@doriantaylor.com"]
  spec.license     = 'Apache-2.0'
  spec.homepage    = 'https://github.com/doriantaylor/rb-lazyauth'
  spec.summary     = 'Rack middleware for extremely lazy Web authentication'
  spec.description = <<-DESC
This little Rack middleware (and attendant command line tool and
rackup app) exists for the purpose of providing rudimentary access
control to a website when the prospective users are both small in
number, and very busy. It circumvents schmucking around provisioning
passwords by generating a link which you can pass to each of your
users through some other mechanism, that when visited logs them in and
keeps them logged in as long as you want. This is basically the
equivalent of having a "forgot password" link without anybody having
to click on "forgot password", and is perfectly adequate security in
certain contexts, namely the ones the author of this gem is interested in.
  DESC

  # switch based on whether we're a git or hg repository
  wd = File.dirname lib
  spec.files = if File.exists?("#{wd}/.git")
                 `git ls-files -z`
               elsif File.exists?("#{wd}/.hg")
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
  spec.add_development_dependency 'bundler', '~> 1.16'
  spec.add_development_dependency 'rake',    '~> 10.0'
  spec.add_development_dependency 'rspec',   '~> 3.0'

  # stuff we use
  spec.add_runtime_dependency 'commander',  '~> 4.4'
  spec.add_runtime_dependency 'deep_merge', '~> 1.2'
  spec.add_runtime_dependency 'dry-schema', '~> 1.0'
  spec.add_runtime_dependency 'fcgi',       '~> 0.9'
  spec.add_runtime_dependency 'iso8601',    '~> 0.12'
  spec.add_runtime_dependency 'rack',       '~> 2.0'
  spec.add_runtime_dependency 'sequel',     '~> 5.20'
  spec.add_runtime_dependency 'uuidtools',  '~> 2.1'

  # stuff i wrote
  spec.add_runtime_dependency 'uuid-ncname', '~> 0.2'
end
