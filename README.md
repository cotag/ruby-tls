# ruby-tls

Ruby-TLS decouples the management of encrypted communications, putting you in charge of the transport layer. It can be used as an alternative to Ruby's SSLSocket.


## Install the gem

Install it with [RubyGems](https://rubygems.org/)

    gem install ruby-tls

or add this to your Gemfile if you use [Bundler](http://gembundler.com/):

    gem "ruby-tls"


Windows users will require an installation of OpenSSL (32bit or 64bit matching the Ruby installation) and be setup with [Ruby Installers DevKit](http://rubyinstaller.org/downloads/)


## Usage

```ruby
require 'rubygems'
require 'ruby-tls'

#
# Create a new TLS connection and attach callbacks
#
connection = RubyTls::Connection.new do |state|
  state.handshake_cb do
    puts "TLS handshake complete"
  end

  state.transmit_cb do |data|
    puts "Data for transmission to remote"
  end

  state.dispatch_cb do |data|
    puts "Clear text data that has been decrypted"
  end

  state.close_cb do |inst, data|
    puts "An error occurred, the transport layer should be shutdown"
  end
end

#
# Init the handshake
#
connection.start

#
# Start sending data to the remote, this will trigger the
# transmit_cb with encrypted data to send.
#
connection.encrypt('client request')

#
# Similarly when data is received from the remote it should be
# passed to connection.decrypt where the dispatch_cb will be
# called with clear text
#
```


## License and copyright

The core SSL code was originally extracted and isolated from [EventMachine](https://github.com/eventmachine/eventmachine/). So is licensed under the same terms, either the GPL or Ruby's License.

