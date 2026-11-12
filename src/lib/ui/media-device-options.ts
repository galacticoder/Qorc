export interface MediaDeviceOption {
  readonly deviceId: string;
  readonly label: string;
}

export function uniqueMediaDevices(devices: readonly MediaDeviceOption[], fallback: string): MediaDeviceOption[] {
  const byId = new Map<string, MediaDeviceOption>();
  for (const device of devices) {
    if (!device.deviceId || byId.has(device.deviceId)) continue;
    byId.set(device.deviceId, {
      deviceId: device.deviceId,
      label: device.label.trim().replace(/\s+/g, ' ') || fallback,
    });
  }
  const counts = new Map<string, number>();
  const key = (label: string) => label.toLowerCase();
  for (const device of byId.values()) counts.set(key(device.label), (counts.get(key(device.label)) ?? 0) + 1);
  const reserved = new Set(counts.keys());
  const next = new Map<string, number>();
  return Array.from(byId.values(), device => {
    const name = key(device.label);
    if (counts.get(name) === 1) return device;
    let index = next.get(name) ?? 1;
    let label: string;
    do { label = `${device.label} (${index++})`; } while (reserved.has(key(label)));
    next.set(name, index);
    reserved.add(key(label));
    return { deviceId: device.deviceId, label };
  });
}
