import { FormEventHandler, useRef } from 'react';
import useSecretValue from './hooks/use-secret-value';

export { SecretsContextProvider } from './context/secrets-context';
export type { SecretValues } from './context/secrets-context';

export function VerifyFlow() {
  const inputRef = useRef(null as HTMLInputElement | null);
  const [secret, setSecret] = useSecretValue('example');

  const handleSubmit: FormEventHandler = (event) => {
    event.preventDefault();

    const nextSecret = inputRef.current?.value;
    if (nextSecret) {
      setSecret(nextSecret);
    }
  };

  return (
    <>
      <div>Secret: {secret}</div>
      <form onSubmit={handleSubmit}>
        <input ref={inputRef} />
        <button type="submit">Submit</button>
      </form>
    </>
  );
}
