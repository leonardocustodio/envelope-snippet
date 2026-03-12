/**
 * User Profile Envelope — Selective per-assertion encryption
 *
 * A user profile where the subject and most assertions are public, but
 * specific links are encrypted to different sets of recipients.
 *
 * Stateless: serialize to CBOR, send over any channel, recipients decrypt
 * with only their private key.
 */

import {
  Envelope,
  SymmetricKey,
  PrivateKeyBase,
  envelopeToBytes,
  envelopeFromBytes,
} from "@bcts/envelope";

// ---------------------------------------------------------------------------
// 1. Recipients generate their own keypairs (out-of-band)
// ---------------------------------------------------------------------------

const alice = PrivateKeyBase.generate(); // profile owner
const bob = PrivateKeyBase.generate(); // close friend
const carol = PrivateKeyBase.generate(); // work colleague
const dave = PrivateKeyBase.generate(); // outsider — no access to anything private

// ---------------------------------------------------------------------------
// 2. Helper: encrypt a link to a set of recipients
// ---------------------------------------------------------------------------

function privateLink(url: string, ...recipients: PrivateKeyBase[]): Envelope {
  const key = SymmetricKey.new();
  let envelope: Envelope = Envelope.new(url).encryptSubject(key);
  // Always include Alice (profile owner)
  envelope = envelope.addRecipient(alice.publicKeys(), key);
  for (const r of recipients) {
    envelope = envelope.addRecipient(r.publicKeys(), key);
  }
  return envelope;
}

// ---------------------------------------------------------------------------
// 3. Build the profile — public subject, public + private assertions
// ---------------------------------------------------------------------------

const profile = Envelope.new("Alice")
  .addType("UserProfile")
  .addAssertion("displayName", "Alice Nakamoto")
  .addAssertion("bio", "Cryptographer & open-source contributor")
  // --- Public links (everyone can read) ---
  .addAssertion("github", "https://github.com/alice")
  .addAssertion("website", "https://alice.dev")
  // --- Private links (encrypted per-recipient) ---
  .addAssertion("telegramGroup", privateLink("https://t.me/secret-dev-chat", bob, carol))
  .addAssertion("privateRepo", privateLink("https://github.com/alice/secret-project", bob))
  .addAssertion("personalEmail", privateLink("alice.real@proton.me", carol));

// ---------------------------------------------------------------------------
// 4. What each person sees
// ---------------------------------------------------------------------------

console.log("=== Profile as seen by anyone (public view) ===");
console.log(profile.format());
console.log();

// --- Bob's view ---
console.log("=== Bob's view ===");
console.log("subject:", profile.subject().asText()); // "Alice" — public
console.log("github:", profile.objectForPredicate("github").extractString()); // public

const bobTelegram = profile.objectForPredicate("telegramGroup");
console.log("telegramGroup:", bobTelegram.decryptSubjectToRecipient(bob).subject().asText());

const bobRepo = profile.objectForPredicate("privateRepo");
console.log("privateRepo:", bobRepo.decryptSubjectToRecipient(bob).subject().asText());

const bobEmail = profile.objectForPredicate("personalEmail");
try {
  bobEmail.decryptSubjectToRecipient(bob);
  console.log("ERROR: Bob should not see personalEmail");
} catch {
  console.log("personalEmail: [no access]");
}
console.log();

// --- Carol's view ---
console.log("=== Carol's view ===");
console.log("subject:", profile.subject().asText());
console.log("github:", profile.objectForPredicate("github").extractString());

const carolTelegram = profile.objectForPredicate("telegramGroup");
console.log("telegramGroup:", carolTelegram.decryptSubjectToRecipient(carol).subject().asText());

const carolRepo = profile.objectForPredicate("privateRepo");
try {
  carolRepo.decryptSubjectToRecipient(carol);
  console.log("ERROR: Carol should not see privateRepo");
} catch {
  console.log("privateRepo: [no access]");
}

const carolEmail = profile.objectForPredicate("personalEmail");
console.log("personalEmail:", carolEmail.decryptSubjectToRecipient(carol).subject().asText());
console.log();

// --- Dave's view (outsider) ---
console.log("=== Dave's view (outsider) ===");
console.log("subject:", profile.subject().asText());
console.log("github:", profile.objectForPredicate("github").extractString());

for (const field of ["telegramGroup", "privateRepo", "personalEmail"]) {
  try {
    profile.objectForPredicate(field).decryptSubjectToRecipient(dave);
    console.log(`ERROR: Dave should not see ${field}`);
  } catch {
    console.log(`${field}: [no access]`);
  }
}
console.log();

// ---------------------------------------------------------------------------
// 5. Serialization round-trip (stateless transmission)
// ---------------------------------------------------------------------------

const bytes = envelopeToBytes(profile);
console.log("Serialized size:", bytes.byteLength, "bytes");

const received = envelopeFromBytes(bytes);
// Bob can still decrypt after deserialization
const recoveredLink = received
  .objectForPredicate("telegramGroup")
  .decryptSubjectToRecipient(bob)
  .subject()
  .asText();
console.log("Bob decrypts after round-trip:", recoveredLink);
