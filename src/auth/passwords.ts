import argon2 from 'argon2';

const ARGON2_OPTIONS = {
  type: argon2.argon2id,
  memoryCost: 19456,
  timeCost: 2,
  parallelism: 1,
} as const;

const COMMON_PASSWORDS = new Set([
  '123456789012',
  '1234567890123',
  '12345678901234',
  'password1234',
  'password12345',
  'contrasena12',
  'contraseña12',
  'contrasena123',
  'contraseña123',
  'qwertyuiop12',
  'qwerty123456',
  'administrador',
  'administrador1',
  'iloveyou1234',
  'welcome12345',
  'letmein12345',
  'aaaaaaaaaaaa',
  '111111111111',
  '000000000000',
  'abc123456789',
]);

export type PasswordPolicyResult = { ok: true } | { ok: false; message: string };

export function checkPasswordPolicy(password: string, email?: string): PasswordPolicyResult {
  if (password.length < 12 || password.length > 128) {
    return {
      ok: false,
      message: 'La contraseña debe tener entre 12 y 128 caracteres.',
    };
  }

  const lowerPassword = password.toLowerCase();
  if (COMMON_PASSWORDS.has(lowerPassword)) {
    return {
      ok: false,
      message: 'La contraseña elegida es demasiado común.',
    };
  }

  if (email !== undefined) {
    const normalizedEmail = email.trim().toLowerCase();
    const atIndex = normalizedEmail.indexOf('@');
    const localPart = atIndex === -1 ? normalizedEmail : normalizedEmail.slice(0, atIndex);
    if (localPart.length >= 4 && lowerPassword.includes(localPart)) {
      return {
        ok: false,
        message: 'La contraseña no puede contener tu nombre de usuario del correo.',
      };
    }
  }

  return { ok: true };
}

export async function hashPassword(password: string): Promise<string> {
  return argon2.hash(password, ARGON2_OPTIONS);
}

export async function verifyPassword(hash: string, password: string): Promise<boolean> {
  try {
    return await argon2.verify(hash, password);
  } catch {
    return false;
  }
}

// Se calcula una sola vez al cargar el módulo con los mismos parámetros argon2id para que
// la verificación ante un usuario inexistente consuma un tiempo equivalente al caso real.
let dummyHashPromise: Promise<string> | undefined;

export async function verifyDummyPassword(password: string): Promise<void> {
  dummyHashPromise ??= hashPassword('clave-ficticia-solo-para-igualar-tiempos-argon2id');
  const hash = await dummyHashPromise;
  await verifyPassword(hash, password);
}
