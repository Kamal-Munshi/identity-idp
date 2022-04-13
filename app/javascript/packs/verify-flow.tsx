import { render } from 'react-dom';
import { VerifyFlow, SecretsContextProvider } from '@18f/identity-verify-flow';
import { encode } from '@18f/identity-secret-session-storage';

const appRoot = document.getElementById('app-root')!;
const key = encode(atob(appRoot.dataset.storeKey!));
const iv = encode(atob(appRoot.dataset.storeIv!));

render(
  <SecretsContextProvider storeKey={key} storeIV={iv}>
    <VerifyFlow />
  </SecretsContextProvider>,
  appRoot,
);
