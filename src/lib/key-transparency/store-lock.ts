export function createStoreLock(): <T>(operation: () => Promise<T>) => Promise<T> {
  let operationChain: Promise<void> = Promise.resolve();
  return async <T>(operation: () => Promise<T>): Promise<T> => {
    const prior = operationChain.catch(() => undefined);
    let release!: () => void;
    operationChain = new Promise<void>((resolve) => { release = resolve; });
    await prior;
    try {
      return await operation();
    } finally {
      release();
    }
  };
}
