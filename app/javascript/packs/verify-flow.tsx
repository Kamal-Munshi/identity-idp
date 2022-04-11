import { render } from 'react-dom';
import { VerifyFlow, SecretValues, SecretsContextProvider } from '@18f/identity-verify-flow';
import SecretSessionStorage, { encode } from '@18f/identity-secret-session-storage';

const appRoot = document.getElementById('app-root')!;
(async () => {
  const key = encode(atob(appRoot.dataset.storeKey!));
  const iv = encode(atob(appRoot.dataset.storeIv!));

  const storage = new SecretSessionStorage<SecretValues>();
  storage.storageKey = 'verify';
  storage.key = await crypto.subtle.importKey('raw', key, 'AES-GCM', true, ['encrypt', 'decrypt']);
  storage.iv = iv;
  await storage.load();

  render(
    <SecretsContextProvider value={storage}>
      <VerifyFlow />
    </SecretsContextProvider>,
    appRoot,
  );
})();
