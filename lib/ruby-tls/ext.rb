require 'ffi'
require 'ffi-compiler/loader'

module RubyTls
    extend FFI::Library
    ffi_lib FFI::Compiler::Loader.find('ruby-tls-ext')


    callback :ssl_close_cb,     [:pointer],                 :void
    callback :ssl_verify_cb,    [:pointer, :string],        :int
    callback :ssl_dispatch_cb,  [:pointer, :pointer, :int], :void
    callback :ssl_transmit_cb,  [:pointer, :pointer, :int], :void
    callback :ssl_handshake_cb, [:pointer],                 :void

    class State < FFI::Struct
        layout  :handshake_sig, :int,

                :close_cb,      :ssl_close_cb,
                :verify_cb,     :ssl_verify_cb,     # Optional
                :dispatch_cb,   :ssl_dispatch_cb,
                :transmit_cb,   :ssl_transmit_cb,
                :handshake_cb,  :ssl_handshake_cb,  # Optional unless first to send data

                :ssl_box,       :pointer
    end


    attach_function :start_tls,     [State.by_ref, :bool, :string, :string, :bool],  :void, :blocking => true
    attach_function :decrypt_data,  [State.by_ref, :pointer, :int],                  :void, :blocking => true
    attach_function :encrypt_data,  [State.by_ref, :pointer, :int],                  :void, :blocking => true
    #attach_function :get_peer_cert, [], :int, :blocking => true
end
