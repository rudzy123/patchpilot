export type Clock = {
  now(): Date;
};

export function createSystemClock(): Clock {
  return {
    now(): Date {
      return new Date();
    },
  };
}
