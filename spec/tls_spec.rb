require 'ruby-tls'

describe RubyTls::Connection do
    before :each do
        #@inst = HttpParser::Parser.new_instance
    end

    describe "FFI Working" do
        it "should return 1" do
            @response = ::RubyTls.testffi
            @response.should == 1
        end
    end
end

