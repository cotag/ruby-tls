require 'ruby-tls'

if RubyTls::SSL::ALPN_SUPPORTED

    describe RubyTls do

        describe RubyTls::SSL::Box do

            it "should be able to negotiate a protocol" do
                @server_data = []
                @client_data = []
                @interleaved = []


                class Client3
                    def initialize(client_data, interleaved)
                        @client_data = client_data
                        @interleaved = interleaved
                        @ssl = RubyTls::SSL::Box.new(false, self, {
                            protocols: ["http/1.1", :h2]
                        })
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
                        @client_data << protocol
                        @interleaved << 'client ready'

                        sending = 'client request'
                        @ssl.encrypt(sending) unless @stop
                    end
                end


                class Server3
                    def initialize(client, server_data, interleaved)
                        @client = client
                        @server_data = server_data
                        @interleaved = interleaved
                        @ssl = RubyTls::SSL::Box.new(true, self, {
                            protocols: [:h2, "http/1.1"]
                        })
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
                        @server_data << protocol
                        @interleaved << 'server ready'
                    end
                end


                @client = Client3.new(@client_data, @interleaved)
                @server = Server3.new(@client, @server_data, @interleaved)
                @client.server = @server


                @client.ssl.start
                @client.ssl.cleanup
                @server.ssl.cleanup

                expect(@server_data).to eq([:h2, 'client request'])
                expect(@client_data).to eq([:h2, 'server response'])
                expect(@interleaved).to eq(['server ready', 'client ready', 'client request', 'server response'])
            end


            it "should stop the server when a protocol cannot be negotiated" do
                @server_data = []
                @client_data = []
                @interleaved = []


                class Client4
                    def initialize(client_data, interleaved)
                        @client_data = client_data
                        @interleaved = interleaved
                        @ssl = RubyTls::SSL::Box.new(false, self, {
                            protocols: ["h2c"]
                        })
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


                class Server4
                    def initialize(client, server_data, interleaved)
                        @client = client
                        @server_data = server_data
                        @interleaved = interleaved
                        @ssl = RubyTls::SSL::Box.new(true, self, {
                            protocols: ["http/1.1", "h2"]
                        })
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


                @client = Client4.new(@client_data, @interleaved)
                @server = Server4.new(@client, @server_data, @interleaved)
                @client.server = @server


                @client.ssl.start
                @client.ssl.cleanup
                @server.ssl.cleanup

                expect(@server_data).to eq(['server stop'])
                expect(@client_data).to eq([])
                expect(@interleaved).to eq(['server stop'])
            end


            it "should not stop the client if the server doesn't support ALPN" do
                @server_data = []
                @client_data = []
                @interleaved = []


                class Client5
                    def initialize(client_data, interleaved)
                        @client_data = client_data
                        @interleaved = interleaved
                        @ssl = RubyTls::SSL::Box.new(false, self, {
                            protocols: ["h2c"]
                        })
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
                        @client_data << protocol
                        @interleaved << 'client ready'

                        sending = 'client request'
                        @ssl.encrypt(sending) unless @stop
                    end
                end


                class Server5
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
                        @server_data << protocol
                        @interleaved << 'server ready'
                    end
                end


                @client = Client5.new(@client_data, @interleaved)
                @server = Server5.new(@client, @server_data, @interleaved)
                @client.server = @server


                @client.ssl.start
                @client.ssl.cleanup
                @server.ssl.cleanup

                expect(@client_data).to eq([:failed, 'server response'])
                expect(@server_data).to eq([nil, 'client request'])
                expect(@interleaved).to eq(['server ready', 'client ready', 'client request', 'server response'])
            end


            it "should not stop the server if the client doesn't support ALPN" do
                @server_data = []
                @client_data = []
                @interleaved = []


                class Client6
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
                        @client_data << protocol
                        @interleaved << 'client ready'

                        sending = 'client request'
                        @ssl.encrypt(sending) unless @stop
                    end
                end


                class Server6
                    def initialize(client, server_data, interleaved)
                        @client = client
                        @server_data = server_data
                        @interleaved = interleaved
                        @ssl = RubyTls::SSL::Box.new(true, self, {
                            protocols: ["h2", "http/1.1"],
                            fallback: "http/1.1"
                        })
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
                        @server_data << protocol
                        @interleaved << 'server ready'
                    end
                end


                @client = Client6.new(@client_data, @interleaved)
                @server = Server6.new(@client, @server_data, @interleaved)
                @client.server = @server


                @client.ssl.start
                @client.ssl.cleanup
                @server.ssl.cleanup


                expect(@server_data).to eq([:"http/1.1", 'client request'])
                expect(@client_data).to eq([nil, 'server response'])
                expect(@interleaved).to eq(['server ready', 'client ready', 'client request', 'server response'])
            end
        end
    end
end
