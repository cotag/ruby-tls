require 'rubygems'
require 'rspec/core/rake_task'  # testing framework
require 'yard'                  # yard documentation


task :default => :spec
RSpec::Core::RakeTask.new(:spec)


desc "Run all tests"
task :test => [:spec]


YARD::Rake::YardocTask.new do |t|
    t.files   = ['lib/**/*.rb', '-', 'ext/README.md', 'README.md']
end
