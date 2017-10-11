require 'ruby-tls'

describe RubyTls do

    describe RubyTls::SSL::Box do

        it "fails when passed an unsupported TLS version" do
            expect {
                RubyTls::SSL::Box.new(false, nil, version: :TLS1_4)
            }.to raise_error(/is unsupported/)
        end

        it "succeeds when passed a supported TLS version" do
            expect {
                RubyTls::SSL::Box.new(false, nil, version: :TLS1_2)
            }.to raise_error(/is unsupported/)
        end

        it "should be able to send and receive encrypted comms" do
            @server_data = []
            @client_data = []
            @interleaved = []


            class Client1
                def initialize(client_data, interleaved)
                    @client_data = client_data
                    @interleaved = interleaved
                    @ssl = RubyTls::SSL::Box.new(false, self)
                end

                attr_reader :ssl
                attr_accessor :stop
                attr_accessor :server

                def close_cb
                    @client_data << 'client stopped'
                    @interleaved << 'client stopped'
                    @stop = true
                end

                def dispatch_cb(data)
                    @client_data << data
                    @interleaved << data
                end

                def transmit_cb(data)
                    if not @server.started
                        @server.started = true
                        @server.ssl.start
                    end
                    @server.ssl.decrypt(data) unless @stop
                end

                def handshake_cb(protocol)
                    @client_data << 'ready'
                    @interleaved << 'client ready'

                    sending = 'client request'
                    @ssl.encrypt(sending) unless @stop
                end
            end


            class Server1
                def initialize(client, server_data, interleaved)
                    @client = client
                    @server_data = server_data
                    @interleaved = interleaved
                    @ssl = RubyTls::SSL::Box.new(true, self)
                end

                attr_reader :ssl
                attr_accessor :started
                attr_accessor :stop

                def close_cb
                    @server_data << 'server stop'
                    @interleaved << 'server stop'
                    @stop = true
                end

                def dispatch_cb(data)
                    @server_data << data
                    @interleaved << data

                    sending = 'server response'
                    @ssl.encrypt(sending) unless @stop
                end

                def transmit_cb(data)
                    @client.ssl.decrypt(data) unless @stop
                end

                def handshake_cb(protocol)
                    @server_data << 'ready'
                    @interleaved << 'server ready'
                end
            end


            @client = Client1.new(@client_data, @interleaved)
            @server = Server1.new(@client, @server_data, @interleaved)
            @client.server = @server


            @client.ssl.start
            @client.ssl.cleanup
            @server.ssl.cleanup


            # Calls to encrypt should not cause crashes after cleanup
            @server.ssl.encrypt('server response')
            @client.ssl.encrypt('client request')

            expect(@server_data).to eq(['ready', 'client request'])
            expect(@client_data).to eq(['ready', 'server response'])
            expect(@interleaved).to eq(['server ready', 'client ready', 'client request', 'server response'])
        end
    end
end

