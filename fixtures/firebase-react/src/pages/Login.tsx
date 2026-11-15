import { signInWithEmailAndPassword } from 'firebase/auth';
import { useState } from 'react';
import { auth } from '../firebase';

export default function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  const submit = async () => {
    const cred = await signInWithEmailAndPassword(auth, email, password);
    const token = await cred.user.getIdToken();
    localStorage.setItem('authToken', token);
    window.location.href = '/';
  };

  return (
    <form onSubmit={(e) => { e.preventDefault(); submit(); }}>
      <input aria-label="Email" value={email} onChange={(e) => setEmail(e.target.value)} />
      <input aria-label="Password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
      <button type="submit">Sign in</button>
    </form>
  );
}
