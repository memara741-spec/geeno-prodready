import { initializeApp } from 'firebase/app';
import { getAuth } from 'firebase/auth';
import { getFirestore } from 'firebase/firestore';
import { getStorage } from 'firebase/storage';

// prodready-fixture: fake. The Firebase web config is public by design.
const firebaseConfig = {
  apiKey: 'AIzaSyFx9aQz7kLm3pRt5vWy2bNc4dHj6g8Ks1P',
  authDomain: 'notely-fake-fixture.firebaseapp.com',
  projectId: 'notely-fake-fixture',
  storageBucket: 'notely-fake-fixture.appspot.com',
  appId: '1:000000000000:web:0000000000000000',
};

export const app = initializeApp(firebaseConfig);
export const auth = getAuth(app);
export const db = getFirestore(app);
export const storage = getStorage(app);
