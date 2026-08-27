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

export function addSeconds(value: Date, seconds: number): Date {
  return new Date(value.getTime() + seconds * 1000);
}
