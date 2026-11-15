import { useEffect, useState } from 'react';
import { collection, getDocs, onSnapshot } from 'firebase/firestore';
import { auth, db } from '../firebase';
import { Note } from '../components/Note';

export default function Feed() {
  const [notes, setNotes] = useState<any[]>([]);
  const [mine, setMine] = useState<any[]>([]);

  useEffect(() => {
    onSnapshot(collection(db, 'notes'), (snap) => {
      setNotes(snap.docs.map((d) => ({ id: d.id, ...d.data() })));
    });
  }, []);

  useEffect(() => {
    getDocs(collection(db, 'notes')).then((snap) => {
      const all = snap.docs.map((d) => ({ id: d.id, ...d.data() })) as any[];
      setMine(all.filter((n) => n.ownerId === auth.currentUser?.uid));
    });
  }, []);

  return (
    <main>
      <h1>Notely</h1>
      <h2>Your notes ({mine.length})</h2>
      {notes.map((n) => <Note key={n.id} note={n} />)}
    </main>
  );
}
