require 'ruby-tls'


describe RubyTls do
    describe RubyTls::Connection do
        before :each do
            @client = RubyTls::Connection.new
            @server = RubyTls::Connection.new

            @server_started  = false
            @server_stop = false
            @client_stop = false

            @dir = File.dirname(File.expand_path(__FILE__)) + '/'
            @cert_from_file = File.read(@dir + 'client.crt')
        end

        it "should verify the peer" do
            @server_data = []
            @client_data = []

            @client.close_cb do
                @client_data << 'close'
                @client_stop = true
            end
            @client.dispatch_cb do |data|
                @client_data << data
            end
            @client.transmit_cb do |data|
                if not @server_started
                    @server_started = true
                    @server.start(:server => true, :verify_peer => true)
                end
                @server.decrypt(data) unless @client_stop
            end
            @client.handshake_cb do
                @client_data << 'ready'
            end

            @server.close_cb do
                @server_data << 'close'
                @server_stop = true
            end
            @server.dispatch_cb do |data|
                @server_data << data
            end
            @server.transmit_cb do |data|
                @client.decrypt(data) unless @server_stop
            end
            @server.handshake_cb do
                @server_data << 'ready'
            end
            @server.verify_cb do |cert|
                @server_data << 'verify'
                @cert_from_server = cert
                true
            end

            @client.start(:private_key_file => @dir + 'client.key', :cert_chain_file => @dir + 'client.crt')

            
            @client_data.should == ['ready']
            @server_data.should == ['verify', 'verify', 'verify', 'ready']
            @cert_from_server.should == @cert_from_file
        end


        it "should deny the connection" do
            @server_data = []
            @client_data = []

            @client.close_cb do
                @client_data << 'close'
                @client_stop = true
            end
            @client.dispatch_cb do |data|
                @client_data << data
            end
            @client.transmit_cb do |data|
                if not @server_started
                    @server_started = true
                    @server.start(:server => true, :verify_peer => true)
                end
                @server.decrypt(data) unless @client_stop
            end
            @client.handshake_cb do
                @client_data << 'ready'
            end

            @server.close_cb do
                @server_data << 'close'
                @server_stop = true
            end
            @server.dispatch_cb do |data|
                @server_data << data
            end
            @server.transmit_cb do |data|
                @client.decrypt(data) unless @server_stop
            end
            @server.handshake_cb do
                @server_data << 'ready'
            end
            @server.verify_cb do |cert|
                @server_data << 'verify'
                @cert_from_server = cert
                false
            end

            @client.start(:private_key_file => @dir + 'client.key', :cert_chain_file => @dir + 'client.crt')

            
            @client_data.should == []
            @server_data.should == ['verify', 'close', 'verify', 'close']
            @cert_from_server.should == @cert_from_file
        end
    end
end

