require 'ffi'
require 'ffi-compiler/loader'

module RubyTls
    extend FFI::Library
    ffi_lib FFI::Compiler::Loader.find('ruby-tls-ext')

    attach_function :testffi, [], :int, :blocking => true
end
