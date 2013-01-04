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

        @rules.parse env, @app
        
      end
    end
  end
end
