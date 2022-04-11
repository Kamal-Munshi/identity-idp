class VerifyController < ApplicationController
  include RenderConditionConcern

  check_or_render_not_found -> { IdentityConfig.store.idv_api_enabled }, only: [:show]

  def show
    @app_data = app_data
  end

  private

  def app_data
    session[:idv_api_store_key] ||= Base64.strict_encode64(OpenSSL::Random.random_bytes(32))
    session[:idv_api_store_iv] ||= Base64.strict_encode64(OpenSSL::Random.random_bytes(12))

    {
      store_key: session[:idv_api_store_key],
      store_iv: session[:idv_api_store_iv],
    }
  end
end
