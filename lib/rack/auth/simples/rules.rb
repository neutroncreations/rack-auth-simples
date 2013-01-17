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
          @codes = []

          @opts = {
            :secret => 'SET_VIA_CONFIG',
            :return_url => '/',
            :cookie_name => '_auth_allowed',
            :fail => :forbidden,
            :code_param => 'code'
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

        def add_trigger_code code, url, target
          @codes << {:code => code, :url => url, :target => target}
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

          if @exceptions.any?
            @exceptions.each do |ex|
              ex = Regexp.new "^#{Regexp.escape ex}$" if ex.is_a? String
              return app.call(env) if  ex =~ env['PATH_INFO']
            end
          end

          ok = true

          if @ips.any?
            addrs_list = IPAddrList.new(@ips)
            return fail unless addrs_list.include? ip
          end

          
          return app.call(env) if get_cookie(env) == @opts[:secret]


          if @triggers.any?

            if @triggers.include? env['PATH_INFO']

              return set_cookie

            end

            ok = false

          end

          if @codes.any?

            @codes.each do |code|

              if code[:url] == env['PATH_INFO'] and code[:code] == Rack::Request.new(env).params[@opts[:code_param]]
                return set_cookie(code[:target])
              end

            end

            ok = false

          end

          # default to true
          return app.call env if ok

          return fail

    		end

        private

          def get_cookie env
            Rack::Request.new(env).cookies[@opts[:cookie_name]]
          end

          def set_cookie url = nil
            headers = {'Location' => ( url || @opts[:return_url] ) }
            Rack::Utils.set_cookie_header!(headers, @opts[:cookie_name], {:value => @opts[:secret], :path => "/"})
            return [302, headers, ['']]
          end


    	end
      
    end
  end
end
