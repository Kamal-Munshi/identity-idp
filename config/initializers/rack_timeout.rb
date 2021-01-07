module Rack
  class Timeout
    @excludes = [
      '/api/verify/images',
      '/verify/doc_auth/selfie',
      '/verify/doc_auth/document_capture',
      '/verify/doc_auth/verify',
      '/verify/capture_doc/document_capture',
      '/verify/recovery/front_image',
      '/verify/recovery/back_image',
      '/verify/recovery/verify',
      '/verify/doc_auth/link_sent',
    ]

    class << self
      attr_accessor :excludes
    end

    def call_with_excludes(env)
      if env['REQUEST_URI'] && env['REQUEST_URI'].start_with?(*self.class.excludes)
        @app.call(env)
      else
        call_without_excludes(env)
      end
    end

    alias call_without_excludes call
    alias call call_with_excludes
  end
end

if Rails.env.development?
  Rails.logger.info 'Disabling Rack::Timeout Logging'
  Rack::Timeout::Logger.disable
end
