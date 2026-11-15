import { assertFails, assertSucceeds, initializeTestEnvironment, type RulesTestEnvironment } from '@firebase/rules-unit-testing';
import { doc, getDoc, setDoc, updateDoc } from 'firebase/firestore';
import { readFileSync } from 'node:fs';
import { afterAll, beforeAll, describe, it } from 'vitest';

let env: RulesTestEnvironment;

beforeAll(async () => {
  env = await initializeTestEnvironment({ projectId: 'notely-test', firestore: { rules: readFileSync('firestore.rules', 'utf8') } });
  await env.withSecurityRulesDisabled(async (ctx) => {
    await setDoc(doc(ctx.firestore(), 'notes/n1'), { ownerId: 'alice', title: 't', body: 'b', sharedWith: [], createdAt: 1 });
    await setDoc(doc(ctx.firestore(), 'users/alice'), { displayName: 'Alice', createdAt: 1 });
  });
});

afterAll(() => env.cleanup());

describe('firestore rules', () => {
  it('lets the owner read a note', async () => {
    await assertSucceeds(getDoc(doc(env.authenticatedContext('alice').firestore(), 'notes/n1')));
  });
  it('blocks another signed-in user from reading it', async () => {
    await assertFails(getDoc(doc(env.authenticatedContext('bob').firestore(), 'notes/n1')));
  });
  it('blocks anonymous visitors', async () => {
    await assertFails(getDoc(doc(env.unauthenticatedContext().firestore(), 'notes/n1')));
  });
  it('blocks a user from giving themselves a role', async () => {
    await assertFails(updateDoc(doc(env.authenticatedContext('alice').firestore(), 'users/alice'), { role: 'admin' }));
  });
});
