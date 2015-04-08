require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class Pinterest < OmniAuth::Strategies::OAuth2
      option :client_options, {
        :site => 'https://pinterest.com',
        :authorize_url => 'https://pinterest.com/oauth/',
        :token_url => 'https://api.pinterest.com/v3/oauth/code_exchange/'
      }

      def request_phase
        options[:scope] ||= 'read'
        options[:response_type] ||= 'code'
        super
      end

      def authorize_params
        super.tap do |params|
          %w[scope client_options client_id].each do |v|
            if request.params[v]
              if v == client_id
                params[:consumer_id] = request.params[v]
              else
                params[v.to_sym] = request.params[v]
              end
            end
          end
        end
      end

      uid { raw_info['id'] }

      info do
        {
          'nickname' => raw_info['username'],
          'name'     => raw_info['full_name'],
          'image'    => raw_info['image_url'],
        }
      end

      def raw_info
        @data ||= access_token.params["user"]
      end
    end
  end
end
