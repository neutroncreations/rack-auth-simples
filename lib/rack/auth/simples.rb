require 'rack/auth/simples/rules'
module Rack
  module Auth
    class Simples

      def initialize app, &block
      	@rules = Rules.new

      	block.call(@rules)

        @app = app
      end

      def call env

      	if @rules.parse_rules
      		@app.call env
      	else
      		return [403, {'Content-Type' => 'text/plain' }, ['Forbidden'] ]
      	end
        
      end
    end
  end
end
