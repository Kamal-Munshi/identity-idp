module RenderConditionConcern
  extend ActiveSupport::Concern

  module ClassMethods
    def check_or_render_not_found(callable, **kwargs)
      before_action(**kwargs) { render_not_found if !callable.call }
    end
  end
end
