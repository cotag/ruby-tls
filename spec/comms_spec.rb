require 'ruby-tls'

describe RubyTls do


    describe RubyTls::State do
        before :each do
            @client = RubyTls::State.new
            @server = RubyTls::State.new

            @server_started  = false
            @server_stop = false
            @client_stop = false
        end

        
        it "should be able to send and receive encrypted comms" do
            @server_data = []
            @client_data = []
            @interleaved = []


            @client[:close_cb] = proc {
                @client_data << 'client stopped'
                @interleaved << 'client stopped'
                @client_stop = true
            }
            @client[:dispatch_cb] = proc { |state, data, len|
                @client_data << data.read_string(len)
                @interleaved << data.read_string(len)
            }
            @client[:transmit_cb] = proc { |state, data, len|
                if not @server_started
                    @server_started = true
                    RubyTls.start_tls(@server, true, '', '', false, '')
                end
                data = data.get_bytes(0, len)
                RubyTls.decrypt_data(@server, data, data.length) unless @client_stop
            }
            @client[:handshake_cb] = proc { |state|
                @client_data << 'ready'
                @interleaved << 'client ready'

                sending = 'client request'
                RubyTls.encrypt_data(@client, sending, sending.length) unless @client_stop
            }


            @server[:close_cb] = proc {
                @server_data << 'server stop'
                @interleaved << 'server stop'
                @server_stop = true
            }
            @server[:dispatch_cb] = proc { |state, data, len|
                @server_data << data.read_string(len)
                @interleaved << data.read_string(len)

                sending = 'server response'
                RubyTls.encrypt_data(@server, sending, sending.length) unless @server_stop
            }
            @server[:transmit_cb] = proc { |state, data, len|
                data = data.get_bytes(0, len)
                RubyTls.decrypt_data(@client, data, data.length) unless @server_stop
            }
            @server[:handshake_cb] = proc { |state|
                @server_data << 'ready'
                @interleaved << 'server ready'
            }

            RubyTls.start_tls(@client, false, '', '', false, '')
            RubyTls.cleanup(@client)
            RubyTls.cleanup(@server)


            
            expect(@client_data).to eq(['ready', 'server response'])
            expect(@server_data).to eq(['ready', 'client request'])
            expect(@interleaved).to eq(['server ready', 'client ready', 'client request', 'server response'])
        end
    end

    describe RubyTls::Connection do
        before :each do
            @client = RubyTls::Connection.new
            @server = RubyTls::Connection.new

            @server_started  = false
            @server_stop = false
            @client_stop = false
        end

        it "should be able to send and receive encrypted comms" do
            @server_data = []
            @client_data = []
            @interleaved = []


            @client.close_cb do
                @client_data << 'client stopped'
                @interleaved << 'client stopped'
                @client_stop = true
            end
            @client.dispatch_cb do |data|
                @client_data << data
                @interleaved << data
            end
            @client.transmit_cb do |data|
                if not @server_started
                    @server_started = true
                    @server.start(:server => true)
                end
                @server.decrypt(data) unless @client_stop
            end
            @client.handshake_cb do
                @client_data << 'ready'
                @interleaved << 'client ready'

                @client.encrypt('client request') unless @client_stop
            end


            @server.close_cb do
                @server_data << 'server stop'
                @interleaved << 'server stop'
                @server_stop = true
            end
            @server.dispatch_cb do |data|
                @server_data << data
                @interleaved << data
                @server.encrypt('server response') unless @server_stop
            end
            @server.transmit_cb do |data|
                @client.decrypt(data) unless @server_stop
            end
            @server.handshake_cb do
                @server_data << 'ready'
                @interleaved << 'server ready'
            end

            @client.start
            @client.cleanup
            @server.cleanup

            # Calls to encrypt should not cause crashes after cleanup
            @server.encrypt('server response')
            @client.encrypt('client request')


            
            expect(@client_data).to eq(['ready', 'server response'])
            expect(@server_data).to eq(['ready', 'client request'])
            expect(@interleaved).to eq(['server ready', 'client ready', 'client request', 'server response'])
        end
    end
end

