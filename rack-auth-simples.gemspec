# -*- encoding: utf-8 -*-
require File.expand_path('../lib/rack-auth-simples/version', __FILE__)

Gem::Specification.new do |gem|
  gem.authors       = ["Roberts, Marc"]
  gem.email         = ["marc@neutroncreations.com"]
  gem.description   = %q{rack middleware for multiple simple auth}
  gem.summary       = %q{rack middleware for multiple simple auth}
  gem.homepage      = "http://github.com/neutroncreations/rack-auth-simples"

  gem.files         = `git ls-files`.split($\)
  gem.executables   = gem.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/.*_spec.rb})
  gem.name          = "rack-auth-simples"
  gem.require_paths = ["lib"]
  gem.add_dependency('ipaddr_list', '>= 0.0.2')
  gem.version       = Rack::Auth::Simples::VERSION
end
