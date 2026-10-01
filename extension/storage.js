export const STORAGE_KEY = 'encryptedVault';

export function sameVault(left, right) {
  const canonical = (value) => JSON.stringify(value, (_, item) =>
    item && typeof item === 'object' && !Array.isArray(item) ?
      Object.fromEntries(Object.keys(item).sort().map((key) => [key, item[key]])) : item);
  return canonical(left) === canonical(right);
}

export class VaultStorage {
  constructor(area, locks) {
    this.area = area;
    this.locks = locks;
  }

  async read() {
    const value = (await this.area.get(STORAGE_KEY))[STORAGE_KEY];
    return value === undefined ? null : value;
  }

  async replace(expected, next, canWrite = () => true) {
    return this.locks.request('easypwd-vault-write', async () => {
      const current = await this.read();
      if (!sameVault(current, expected)) {
        throw new Error('The vault changed in another tab. Unlock again before saving.');
      }
      if (!canWrite()) throw new Error('The vault was locked. No changes were saved.');
      if (next === null) await this.area.remove(STORAGE_KEY);
      else await this.area.set({ [STORAGE_KEY]: next });
    });
  }
}
