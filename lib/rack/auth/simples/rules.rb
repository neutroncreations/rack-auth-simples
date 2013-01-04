require 'ipaddr'
require 'ipaddr_list'
module Rack
  module Auth
    
    class Simples

    	class Rules

    		def initialize
    			@ips = []
    			@triggers = []
          @exceptions = []

          @opts = {
            :secret => 'SET_VIA_CONFIG',
            :return_url => '/',
            :cookie_name => '_auth_allowed',
            :fail => :forbidden
          }
    		end

        def set_options opts
          @opts.merge! opts
        end

    		def add_ip ip
    			@ips << ip
    		end

        def add_exception url
          @exceptions << url
        end

        def allow_local
          @ips << '127.0.0.1'
        end

    		def add_trigger_url url
    			@triggers << url
    		end

    		def parse env, app

          if @opts[:fail] == :forbidden
            fail = [403, {'Content-Type' => 'text/plain' }, ['Forbidden'] ]
          else 
            fail = [302, {'Location' => @opts[:fail] }, [] ]
          end

          if env['HTTP_X_FORWARDED_FOR']
            ip = env['HTTP_X_FORWARDED_FOR'].split(',').pop
          else
            ip = env["REMOTE_ADDR"]
          end

          return app.call(env) if @exceptions.include? env['PATH_INFO']

          if @ips.any?
            addrs_list = IPAddrList.new(@ips)
            return fail unless addrs_list.include? ip
          end

          if @triggers.any?

            cookie = Rack::Request.new(env).cookies[@opts[:cookie_name]]

            return app.call(env) if cookie == @opts[:secret]

            if @triggers.include? env['PATH_INFO']

              headers = {'Location' => @opts[:return_url]}
              Rack::Utils.set_cookie_header!(headers, @opts[:cookie_name], {:value => @opts[:secret], :path => "/"})
              return [302, headers, ['']]

            end

            return fail

          end

          # default to true
          return app.call env

    		end


    	end
      
    end
  end
end
