import { deleteUser } from 'firebase/auth';
import { collection, deleteDoc, doc, getDocs, limit, query, where } from 'firebase/firestore';
import { useState } from 'react';
import { auth, db } from '../firebase';

export default function Account() {
  const [pending, setPending] = useState(false);
  const [message, setMessage] = useState('');

  const deleteAccount = async () => {
    const user = auth.currentUser;
    if (!user) return;
    setPending(true);
    try {
      const mine = await getDocs(query(collection(db, 'notes'), where('ownerId', '==', user.uid), limit(500)));
      await Promise.all(mine.docs.map((d) => deleteDoc(d.ref)));
      await deleteDoc(doc(db, 'users', user.uid));
      await deleteUser(user);
      setMessage('Your account and notes were deleted.');
    } catch (error) {
      setMessage('Could not delete the account. Sign in again and retry.');
      throw error;
    } finally {
      setPending(false);
    }
  };

  return (
    <main>
      <h1>Account</h1>
      <button type="button" disabled={pending} onClick={deleteAccount}>Delete my account and data</button>
      <p role="status">{message}</p>
    </main>
  );
}
