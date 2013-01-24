require 'ipaddr'
require 'ipaddr_list'

require 'digest/md5'

module Rack
  module Auth
    
    class Simples

    	class Rules

    		def initialize
    			@ips = []
    			@triggers = []
          @exceptions = []
          @codes = []
          @fb = false

          @opts = {
            :secret => 'SET_VIA_CONFIG',
            :return_url => '/',
            :cookie_name => '_auth_allowed',
            :fail => :forbidden,
            :code_param => 'code',
            :days => 14
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

        def allow_facebook
          @fb = true
        end

    		def add_trigger_url url
    			@triggers << url
    		end

        def add_trigger_code code, url, target
          @codes << {:code => code, :url => url, :target => target}
        end

    		def parse env, app

          return app.call(env) if @fb && env['HTTP_USER_AGENT'] =~ /facebookexternalhit/

          if @opts[:fail] == :forbidden
            fail = [403, {'Content-Type' => 'text/plain' }, ['Forbidden'] ]
          else 
            fail = [302, {'Content-Type' => '', 'Location' => @opts[:fail] }, [] ]
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

          
          return update_cookie(app.call env) if check_cookie(env)


          if @triggers.any?

            if @triggers.include? env['PATH_INFO']

              return set_cookie

            end

            ok = false

          end

          if @codes.any?

            @codes.each do |code|

              if code[:url] == env['PATH_INFO'] and code[:code].downcase == Rack::Request.new(env).params[@opts[:code_param]].downcase
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

          def check_cookie env
            value = Rack::Request.new(env).cookies[@opts[:cookie_name]]
            
            if value.nil?
              return false
            else
              time, hash = value.split('.')
              expiry = time.to_i
              return ( (expiry > Time.now.to_i) && (hash == cookie_hash(expiry)) )
            end

          end

          def cookie_hash time = Time.now.to_i
            ::Digest::MD5.hexdigest "#{time.to_s}---#{@opts[:secret]}"
          end

          def cookie
            expires = (Time.now + @opts[:days] * 86400)
            {
              :value => "#{expires.to_i.to_s}.#{cookie_hash expires.to_i}", 
              :path => "/",
              :expires => expires
            }
          end

          def set_cookie url = nil
            headers = {'Content-Type' => '', 'Location' => ( url || @opts[:return_url] ) }
            Rack::Utils.set_cookie_header!(headers, @opts[:cookie_name], cookie)
            return [302, headers, ['']]
          end

          def update_cookie response
            status, headers, body = response
            Rack::Utils.set_cookie_header!(headers, @opts[:cookie_name], cookie)
            return [status, headers, body]
          end


    	end
      
    end
  end
end
