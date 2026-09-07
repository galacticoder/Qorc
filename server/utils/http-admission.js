export function createInflightBodyAdmission({ maxInflight, onReject } = {}) {
  if (!Number.isSafeInteger(maxInflight) || maxInflight < 1 || maxInflight > 256) {
    throw new Error('Invalid body admission limit');
  }
  if (onReject !== undefined && typeof onReject !== 'function') {
    throw new Error('Invalid body admission rejection handler');
  }

  let inflight = 0;
  return function inflightBodyAdmission(req, res, next) {
    if (inflight >= maxInflight) {
      onReject?.();
      try { req.destroy?.(); } catch { }
      try { res.destroy?.(); } catch { }
      return;
    }

    inflight += 1;
    let released = false;
    const release = () => {
      if (released) return;
      released = true;
      inflight = Math.max(0, inflight - 1);
      res.off?.('finish', release);
      res.off?.('close', release);
      res.off?.('error', release);
    };
    res.once?.('finish', release);
    res.once?.('close', release);
    res.once?.('error', release);
    try {
      next();
    } catch (error) {
      release();
      throw error;
    }
  };
}
