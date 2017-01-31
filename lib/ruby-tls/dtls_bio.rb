# frozen_string_literal: true



module RubyTls::SSL
    typedef :pointer, :bio_methods_ptr
    attach_function :BIO_get_new_index, [], :int
    attach_function :BIO_meth_new, [:int, :buffer_in], :bio_methods_ptr

    callback :bio_write_cb, [:bio, :pointer, :int], :int
    attach_function :BIO_meth_set_write,   [:bio_methods_ptr, :bio_write_cb], :int

    callback :bio_ctrl_cb, [:bio, :int, :long, :pointer], :long
    attach_function :BIO_meth_set_ctrl,    [:bio_methods_ptr, :bio_ctrl_cb], :int

    callback :bio_create_cb, [:bio], :int
    attach_function :BIO_meth_set_create,  [:bio_methods_ptr, :bio_create_cb], :int

    callback :bio_destroy_cb, [:bio], :int
    attach_function :BIO_meth_set_destroy, [:bio_methods_ptr, :bio_destroy_cb], :int

    attach_function :BIO_set_init, [:bio, :int], :void
    attach_function :BIO_set_data, [:bio, :pointer], :void
    attach_function :BIO_get_data, [:bio], :pointer


    attach_function :DTLS_server_method, [], :pointer
    attach_function :DTLS_client_method, [], :pointer


    module DTLS
        BIO_TYPE_FILTER = 0x0200

        BioWriteCB = FFI::Function.new(:int, [:bio, :pointer, :int]) do |bio, data_ptr, data_len|

        end

        BioCtrlCB = FFI::Function.new(:long, [:bio, :int, :long, :pointer]) do |bio, cmd, num, ptr|
            
        end

        BioCreateCB = FFI::Function.new(:int, [:bio]) do |bio|
            BIO_set_init(bio, 1)
        end

        BioDestroyCB = FFI::Function.new(:int, [:bio]) do |bio|
            BIO_set_init(bio, 0)
        end


        @init_performed ||= false
        unless @init_performed
            bio_methods_ptr = SSL.BIO_meth_new(BIO_TYPE_FILTER | SSL.BIO_get_new_index, 'ruby dtls filter')
            if bio_methods_ptr.null?
                raise 'unable to init DTLS BIO - NULL pointer'
            end

            SSL.BIO_meth_set_write(bio_methods_ptr, BioWriteCB)
            SSL.BIO_meth_set_ctrl(bio_methods_ptr, BioCtrlCB)
            SSL.BIO_meth_set_create(bio_methods_ptr, BioCreateCB)
            SSL.BIO_meth_set_destroy(bio_methods_ptr, BioDestroyCB)

            @init_performed = true
        end


        class Box
            InstanceLookup = ::Concurrent::Map.new
            DTLS_MTU = 1472


        end



        class Context
            CIPHERS = "ALL:NULL:eNULL:aNULL"

            def initialize(server, options = {})
                @is_server = server
                @ssl_ctx = SSL.SSL_CTX_new(server ? SSL.DTLS_server_method : SSL.DTLS_client_method)

                if @is_server
                    set_private_key(options[:private_key] || SSL::DEFAULT_PRIVATE)
                    set_certificate(options[:cert_chain]  || SSL::DEFAULT_CERT)
                    set_client_ca(options[:client_ca])
                end

                SSL.SSL_CTX_set_cipher_list(@ssl_ctx, options[:ciphers] || CIPHERS)
                @alpn_set = false
            end
        end
    end
end
