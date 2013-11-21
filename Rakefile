require 'rubygems'
require 'rake'
require 'rspec/core/rake_task'

task :default => [:compile, :test]

task :compile do
    protect = ['ssl.cpp', 'ssl.h', 'page.cpp', 'page.h']
    Dir["ext/tls/**/*"].each do |file|
        begin
            next if protect.include? File.basename(file)
            FileUtils.rm file
        rescue
        end
    end
    system 'cd ext && rake'
end

RSpec::Core::RakeTask.new(:test)
