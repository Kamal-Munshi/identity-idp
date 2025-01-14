import sinon from 'sinon';
import { render } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import PersonalKeyConfirmStep from './personal-key-confirm-step';

describe('PersonalKeyConfirmStep', () => {
  const DEFAULT_PROPS = {
    onChange() {},
    value: { personalKey: '' },
    errors: [],
    unknownFieldErrors: [],
    onError() {},
    registerField: () => () => {},
  };

  it('allows the user to return to the previous step by clicking "Back" button', () => {
    const toPreviousStep = sinon.spy();
    const { getByText } = render(
      <PersonalKeyConfirmStep {...DEFAULT_PROPS} toPreviousStep={toPreviousStep} />,
    );

    userEvent.click(getByText('forms.buttons.back'));

    expect(toPreviousStep).to.have.been.called();
  });

  it('allows the user to return to the previous step by pressing Escape', () => {
    const toPreviousStep = sinon.spy();
    const { getByRole } = render(
      <PersonalKeyConfirmStep {...DEFAULT_PROPS} toPreviousStep={toPreviousStep} />,
    );

    userEvent.type(getByRole('textbox'), '{esc}');

    expect(toPreviousStep).to.have.been.called();
  });
});
