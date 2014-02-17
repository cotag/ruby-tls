
module RubyTls
    class Connection
        CALLBACKS = [:close_cb, :verify_cb, :dispatch_cb, :transmit_cb, :handshake_cb].freeze
        Callbacks = Struct.new(*CALLBACKS)

        #
        # Initializes the State instance.
        #
        def initialize(callback_obj = nil)
            @state = ::RubyTls::State.new
            @callbacks = Callbacks.new      # so GC doesn't clean them up on java
            @started = false

            # Attach callbacks if there is an object passed in to handle the callbacks
            if not callback_obj.nil?
                CALLBACKS.each do |callback|
                    self.__send__(callback, &callback_obj.method(callback)) if callback_obj.respond_to? callback
                end
            end

            yield self if block_given?
        end

        def close_cb(&block)
            cb = Callback.new(@callbacks, &block)
            @callbacks[:close_cb] = cb
            @state[:close_cb] = cb
        end

        def verify_cb
            cb = ::FFI::Function.new(:int, [::RubyTls::State.ptr, :string]) do |state, cert|
                begin
                    yield(cert) == true ? 1 : 0
                rescue
                    # TODO:: Provide some debugging output
                    0
                end
            end
            @callbacks[:verify_cb] = cb
            @state[:verify_cb] = cb
        end

        def dispatch_cb(&block)
            cb = DataCallback.new(@callbacks, &block)
            @callbacks[:dispatch_cb] = cb
            @state[:dispatch_cb] = cb
        end

        def transmit_cb(&block)
            cb = DataCallback.new(@callbacks, &block)
            @callbacks[:transmit_cb] = cb
            @state[:transmit_cb] = cb
        end

        def handshake_cb(&block)
            cb = Callback.new(@callbacks, &block)
            @callbacks[:handshake_cb] = cb
            @state[:handshake_cb] = cb
        end


        def start(args = {})
            return if @started

            server, priv_key, cert_chain, verify_peer = args.values_at(:server, :private_key_file, :cert_chain_file, :verify_peer)
            [priv_key, cert_chain].each do |file|
                next if file.nil? or file.empty?
                raise FileNotFoundException,
                "Could not find #{file} to start tls" unless File.exists? file
            end
            @started = true
            ::RubyTls.start_tls(@state, server || false, priv_key || '', cert_chain || '', verify_peer || !!@callbacks[:verify_cb])
        end

        def encrypt(data)
            ::RubyTls.encrypt_data(@state, data, data.length)
        end

        def decrypt(data)
            ::RubyTls.decrypt_data(@state, data, data.length)
        end

        def cleanup
            ::RubyTls.cleanup(@state)
        end


        protected


        class Callback < ::FFI::Function
            #
            # Creates a new Parser callback.
            #
            def self.new(callbacks)
                super(:void, [::RubyTls::State.ptr]) do |state|
                    begin
                        yield
                    rescue => e
                        # shutdown the connection on error
                        # TODO:: Provide some debugging output
                        callbacks[:close_cb].call state
                    end
                end
            end
        end

        class DataCallback < ::FFI::Function
            def self.new(callbacks)
                super(:void, [::RubyTls::State.ptr, :pointer, :int]) do |state, buffer, length|
                    begin
                        data = buffer.get_bytes(0, length)
                        yield(data)
                    rescue => e
                        # shutdown the connection on error
                        # TODO:: Provide some debugging output
                        callbacks[:close_cb].call state
                    end
                end
            end
        end
    end
end
