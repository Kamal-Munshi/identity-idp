class CancellationPresenter < FailurePresenter
  include ActionView::Helpers::TranslationHelper
  include Rails.application.routes.url_helpers

  attr_reader :referer

  def initialize(referer:)
    super(:warning)
    @referer = referer
  end

  def title
    t('headings.cancellations.prompt')
  end

  def header
    t('headings.cancellations.prompt')
  end

  def cancellation_warnings
    [
      t('users.delete.bullet_1', app: APP_NAME),
      t('users.delete.bullet_2_loa1'),
      t('users.delete.bullet_3', app: APP_NAME),
    ]
  end

  def go_back_path
    referer_path || two_factor_options_path
  end

  private

  def referer_path
    return if referer.blank?
    referer_uri = URI.parse(referer)
    return if referer_uri.scheme == 'javascript'
    return unless referer_uri.host == AppConfig.env.domain_name.split(':')[0]
    extract_path_and_query_from_uri(referer_uri)
  end

  def extract_path_and_query_from_uri(uri)
    [uri.path, uri.query].compact.join('?')
  end
end
