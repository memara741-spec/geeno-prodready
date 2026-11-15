import { collection, limit, onSnapshot, orderBy, query, where } from 'firebase/firestore';
import { useEffect, useState } from 'react';
import { auth, db } from '../firebase';

type Note = { id: string; title: string; body: string };

export default function Feed() {
  const [notes, setNotes] = useState<Note[]>([]);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    const uid = auth.currentUser?.uid;
    if (!uid) return;
    const mine = query(collection(db, 'notes'), where('ownerId', '==', uid), orderBy('createdAt', 'desc'), limit(50));
    const unsubscribe = onSnapshot(
      mine,
      (snap) => setNotes(snap.docs.map((d) => ({ id: d.id, title: d.get('title'), body: d.get('body') }))),
      () => setFailed(true),
    );
    return () => unsubscribe();
  }, []);

  if (failed) return <p>Could not load your notes. Check your connection and reload.</p>;
  if (notes.length === 0) return <p>No notes yet. Write your first one.</p>;

  return (
    <main>
      <h1>Your notes</h1>
      {notes.map((n) => (
        <article key={n.id}>
          <h2>{n.title}</h2>
          <p>{n.body}</p>
        </article>
      ))}
    </main>
  );
}
