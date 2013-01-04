require 'ipaddr'
require 'ipaddr_list'
module Rack
  module Auth
    
    class Simples

    	class Rules

    		def initialize
    			@ips = []
    			@triggers = []	
    		end

    		def add_ip ip
    			@ips << ip
    		end

        def allow_local
          @ips << '127.0.0.1'
        end

    		def add_trigger_url url
    			@triggers << url
    		end

    		def parse_rules env

          if env['HTTP_X_FORWARDED_FOR']
            ip = env['HTTP_X_FORWARDED_FOR'].split(',').pop
          else
            ip = env["REMOTE_ADDR"]
          end


          if @ips.any?
            addrs_list = IPAddrList.new(@ips)
            return false unless addrs_list.include? ip
          end

          if @triggers.any?

            # check cookie, return true if present

            # check trigger url, if match set cookie and return true

            # return false

          end

          # default to true
          return true

    		end


    	end
      
    end
  end
end
