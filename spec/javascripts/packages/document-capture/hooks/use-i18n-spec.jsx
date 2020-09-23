import React from 'react';
import { renderHook } from '@testing-library/react-hooks';
import I18nContext from '@18f/identity-document-capture/context/i18n';
import useI18n, { formatHTML } from '@18f/identity-document-capture/hooks/use-i18n';
import render from '../../../support/render';

describe('document-capture/hooks/use-i18n', () => {
  describe('formatHTML', () => {
    it('returns html string treated as escaped text without handler', () => {
      const formatted = formatHTML('Hello <strong>world</strong>!', {});

      const { container } = render(formatted);

      expect(container.innerHTML).to.equal('Hello &lt;strong&gt;world&lt;/strong&gt;!');
    });

    it('returns html string chunked by handlers', () => {
      const formatted = formatHTML('Hello <strong>world</strong>!', {
        strong: ({ children }) => <strong>{children}</strong>,
      });

      const { container } = render(formatted);

      expect(container.innerHTML).to.equal('Hello <strong>world</strong>!');
    });

    it('returns html string chunked by multiple handlers', () => {
      const formatted = formatHTML(
        'Message: <lg-custom>Hello</lg-custom> <strong>world</strong>!',
        {
          'lg-custom': () => 'Greetings',
          strong: ({ children }) => <strong>{children}</strong>,
        },
      );

      const { container } = render(formatted);

      expect(container.innerHTML).to.equal('Message: Greetings <strong>world</strong>!');
    });

    it('removes dangling empty text fragment', () => {
      const formatted = formatHTML('Hello <strong>world</strong>', {
        strong: ({ children }) => <strong>{children}</strong>,
      });

      const { container } = render(formatted);

      expect(container.childNodes).to.have.lengthOf(2);
    });
  });

  describe('t', () => {
    it('returns localized key value', () => {
      const { result } = renderHook(() => useI18n(), {
        wrapper: ({ children }) => (
          <I18nContext.Provider value={{ sample: 'translation' }}>{children}</I18nContext.Provider>
        ),
      });

      const { t } = result.current;

      expect(t('sample')).to.equal('translation');
    });

    it('falls back to key value', () => {
      const { result } = renderHook(() => useI18n());

      const { t } = result.current;

      expect(t('sample')).to.equal('sample');
    });
  });
});
