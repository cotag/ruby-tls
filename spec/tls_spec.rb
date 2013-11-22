require 'ruby-tls'

describe RubyTls::Connection do
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
                RubyTls.start_tls(@server, true, '', '', false)
            end
            RubyTls.decode_data(@server, data, len) unless @client_stop
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
            RubyTls.decode_data(@client, data, len) unless @server_stop
        }
        @server[:handshake_cb] = proc { |state|
            @server_data << 'ready'
            @interleaved << 'server ready'
        }

        RubyTls.start_tls(@client, false, '', '', false)


        
        @client_data.should == ['ready', 'server response']
        @server_data.should == ['ready', 'client request']
        @interleaved.should == ['server ready', 'client ready', 'client request', 'server response']
    end
end

