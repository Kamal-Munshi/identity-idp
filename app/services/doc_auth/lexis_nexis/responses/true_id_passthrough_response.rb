# frozen_string_literal: true

module DocAuth
  module LexisNexis
    module Responses
      class TrueIdPassthroughResponse < DocAuth::Acuant::Responses::GetResultsResponse
        PII_EXCLUDES = DocAuth::LexisNexis::Responses::TrueIdResponse::PII_EXCLUDES
        PII_INCLUDES = DocAuth::LexisNexis::Responses::TrueIdResponse::PII_INCLUDES

        attr_reader :config

        def initialize(http_response, liveness_checking_enabled, config)
          @liveness_checking_enabled = liveness_checking_enabled
          @config = config

          super acuant_response(http_response), config
        end

        def acuant_response(http_response)
          parsed_response = parsed_trueid_response_body(http_response)
          Ahoy::Tracker.new.track('Acuant Passthrough API Response', just_keys(parsed_response))
          acuant_body = parsed_response["PassThroughs"][0]["Data"]
          OpenStruct.new(body: acuant_body)
        end

        def parsed_trueid_response_body(http_response)
          @parsed_trueid_response_body ||= JSON.parse(http_response.body)
        end

        def just_keys(hash)
          hash.to_h do |key, value|
            if value.is_a?(Hash)
              [key, just_keys(value)]
            else
              [key, 'redacted']
            end
          end
        end

        def error_messages
          generate_errors
        end

        def extra_attributes
          response_info
        end
      end
    end
  end
end
