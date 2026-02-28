import { describe, expect, it } from 'vitest';
import phpPassword from '../index.js';

describe('php-password', () => {
  it('hash/verify が動作する', () => {
    const password = 'passw0rd';
    const passwordHash = phpPassword.hash(password);

    expect(phpPassword.verify(password, passwordHash)).toBe(true);
    expect(phpPassword.verify('wrong', passwordHash)).toBe(false);
  });

  it('get_info で bcrypt の情報を返す', () => {
    const passwordHash = phpPassword.hash('passw0rd', phpPassword.PASSWORD_BCRYPT, { cost: 11 });
    const info = phpPassword.get_info(passwordHash);

    expect(info).toEqual({
      algo: phpPassword.PASSWORD_BCRYPT,
      algoName: 'bcrypt',
      options: { cost: 11 },
    });
  });

  it('needs_rehash がコスト差分を判定する', () => {
    const passwordHash = phpPassword.hash('passw0rd', phpPassword.PASSWORD_BCRYPT, { cost: 10 });

    expect(phpPassword.needs_rehash(passwordHash, phpPassword.PASSWORD_BCRYPT, { cost: 10 })).toBe(false);
    expect(phpPassword.needs_rehash(passwordHash, phpPassword.PASSWORD_BCRYPT, { cost: 12 })).toBe(true);
  });

  it('PHP スタイル API エイリアスを提供する', () => {
    const password = 'passw0rd';
    const passwordHash = phpPassword.password_hash(password, '2y', { cost: 10 });

    expect(phpPassword.password_verify(password, passwordHash)).toBe(true);
    expect(phpPassword.password_needs_rehash(passwordHash, 'bcrypt', { cost: 10 })).toBe(false);
    expect(phpPassword.password_get_info(passwordHash).algoName).toBe('bcrypt');
    expect(phpPassword.password_algos()).toEqual(['2y']);
  });
});
