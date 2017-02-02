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

    attach_function :DTLS_server_method, [], :pointer
    attach_function :DTLS_client_method, [], :pointer

    #                                  cookie str  str length  ret 1 on success
    callback :cookie_generate_cb, [:ssl, :pointer, :pointer], :int
    attach_function :SSL_CTX_set_cookie_generate_cb, [:ssl_ctx, :cookie_generate_cb], :void

    #                                cookie str  str length  ret 1 on success
    callback :cookie_verify_cb, [:ssl, :pointer, :uint], :int
    attach_function :SSL_CTX_set_cookie_verify_cb, [:ssl_ctx, :cookie_verify_cb], :void


    # Curves are automatically enabled on OpenSSL V1.1
    # Earlier versions require them to be enabled manually
    begin
        attach_function :SSL_CTX_set_ecdh_auto, [:ssl_ctx, :int], :int
        EnableCurves = true
    rescue FFI::NotFoundError
        EnableCurves = false
    end


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
            BioMethodsPtr = SSL.BIO_meth_new(BIO_TYPE_FILTER | SSL.BIO_get_new_index, 'ruby dtls filter')
            if BioMethodsPtr.null?
                raise 'unable to init DTLS BIO - NULL pointer'
            end

            SSL.BIO_meth_set_write(BioMethodsPtr, BioWriteCB)
            SSL.BIO_meth_set_ctrl(BioMethodsPtr, BioCtrlCB)
            SSL.BIO_meth_set_create(BioMethodsPtr, BioCreateCB)
            SSL.BIO_meth_set_destroy(BioMethodsPtr, BioDestroyCB)

            @init_performed = true
        end



        class Context
            CIPHERS = 'ALL:NULL:eNULL:aNULL'
            SESSION = 'ruby-tls'

            def initialize(server, options = {})
                @is_server = server
                @ssl_ctx = SSL.SSL_CTX_new(server ? SSL.DTLS_server_method : SSL.DTLS_client_method)

                SSL.SSL_CTX_set_cipher_list(@ssl_ctx, options[:ciphers] || CIPHERS)
                @alpn_set = false

                if @is_server
                    set_private_key(options[:private_key] || SSL::DEFAULT_PRIVATE)
                    set_certificate(options[:cert_chain]  || SSL::DEFAULT_CERT)
                    set_client_ca(options[:client_ca])

                    SSL.SSL_CTX_sess_set_cache_size(@ssl_ctx, 128)
                    SSL.SSL_CTX_set_session_id_context(@ssl_ctx, SESSION, 8)

                    if options[:protocols]
                        @alpn_str = Context.build_alpn_string(options[:protocols])
                        SSL.SSL_CTX_set_alpn_select_cb(@ssl_ctx, SSL::Context::ALPN_Select_CB, nil)
                        @alpn_set = true
                    end
                else
                    set_private_key(options[:private_key])
                    set_certificate(options[:cert_chain])

                    # Check for ALPN support
                    if options[:protocols]
                        protocols = Context.build_alpn_string(options[:protocols])
                        @alpn_set = SSL.SSL_CTX_set_alpn_protos(@ssl_ctx, protocols, protocols.length) == 0
                    end
                end

                # NOTE:: Enable 
                SSL.SSL_CTX_set_ecdh_auto(@ssl_ctx, 1) if SSL::EnableCurves
            end
        end
    end
end
