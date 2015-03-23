# ruby-tls

Ruby-TLS decouples the management of encrypted communications, putting you in charge of the transport layer. It can be used as an alternative to Ruby's SSLSocket.

[![Build Status](https://travis-ci.org/cotag/ruby-tls.png?branch=master)](https://travis-ci.org/cotag/ruby-tls)


## Install the gem

Install it with [RubyGems](https://rubygems.org/)

    gem install ruby-tls

or add this to your Gemfile if you use [Bundler](http://gembundler.com/):

    gem "ruby-tls"


Windows users will require an installation of OpenSSL (32bit or 64bit matching the Ruby installation)


## Usage

```ruby
require 'rubygems'
require 'ruby-tls'

class transport
  def initialize
    is_server = true
    callback_obj = self
    options = {
      verify_peer: true,
      private_key: '/file/path.pem',
      cert_chain: '/file/path.crt',
      ciphers: 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-RC4-SHA:ECDHE-RSA-AES128-SHA:AES128-GCM-SHA256:RC4:HIGH:!MD5:!aNULL:!EDH:!CAMELLIA:@STRENGTH' # (default)
      # protocols: ["h2", "http/1.1"], # Can be used where OpenSSL >= 1.0.2 (Application Level Protocol negotiation)
      # fallback: "http/1.1" # Optional fallback to a default protocol when either client or server doesn't support ALPN
    }
    @ssl_layer = RubyTls::SSL::Box.new(is_server, callback_obj, options)
  end

  def close_cb
    puts "The transport layer should be shutdown"
  end

  def dispatch_cb(data)
    puts "Clear text data that has been decrypted"
  end

  def transmit_cb(data)
    puts "Encrypted data for transmission to remote"
    # @tcp.send data
  end

  def handshake_cb(protocol)
    puts "initial handshake has completed"
  end

  def verify_cb(cert)
    # Return true or false
    is_cert_valid? cert
  end

  def start_tls
    # Start SSL negotiation when you are ready
    @ssl_layer.start
  end

  def send(data)
    @ssl_layer.encrypt(data)
  end
end

#
# Create a new TLS connection
#
connection = transport.new

#
# Init the handshake
#
connection.start_tls

#
# Start sending data to the remote, this will trigger the
# transmit_cb with encrypted data to send.
#
connection.send('client request')

#
# Similarly when data is received from the remote it should be
# passed to connection.decrypt where the dispatch_cb will be
# called with clear text
#
```


## License and copyright

MIT

