import { exactRedisScoreArgument } from './redis-args.js';

function redisSortedSetLeaseReleaseGuard(scoreArgumentIndex) {
  return `
  local currentScore = redis.call('ZSCORE', KEYS[1], ARGV[1])
  if not currentScore or tonumber(currentScore) ~= tonumber(ARGV[${scoreArgumentIndex}]) then return 0 end
  if redis.call('ZREM', KEYS[1], ARGV[1]) ~= 1 then return 0 end
`;
}

const MOVE_REDIS_SORTED_SET_LEASE_SCRIPT = `
${redisSortedSetLeaseReleaseGuard(4)}
  redis.call('ZADD', KEYS[2], ARGV[2], ARGV[1])
  redis.call('EXPIRE', KEYS[1], ARGV[3])
  redis.call('EXPIRE', KEYS[2], ARGV[3])
  return 1
`;

export const REDIS_SORTED_SET_LEASE_RELEASE_GUARD = redisSortedSetLeaseReleaseGuard(3);

export async function moveRedisSortedSetLease(client, {
  sourceKey,
  destinationKey,
  member,
  destinationScore,
  ttlSeconds,
  expectedSourceScore,
  scoreContext = 'lease'
}) {
  const sourceScore = exactRedisScoreArgument(expectedSourceScore, scoreContext);
  return Number(await client.eval(
    MOVE_REDIS_SORTED_SET_LEASE_SCRIPT,
    2,
    sourceKey,
    destinationKey,
    member,
    destinationScore,
    ttlSeconds,
    sourceScore
  )) === 1;
}
