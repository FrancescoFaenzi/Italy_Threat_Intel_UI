import { getSnapshotCount, hasSnapshotForDate } from './db.ts';
import { getCetDateAndHour, runIngestion } from './ingest.ts';

let schedulerStarted = false;

export function startScheduler(): void {
  if (schedulerStarted) return;
  schedulerStarted = true;

  // Startup bootstrap & auto-catchup after 8:00 AM CET
  const checkAndTrigger = async (reason: 'startup' | 'interval') => {
    const { dateCet, hourCet } = getCetDateAndHour();
    const hasToday = hasSnapshotForDate(dateCet);
    const totalSnapshots = getSnapshotCount();

    if (totalSnapshots === 0) {
      console.log(`[scheduler] Fresh database detected on ${reason}; running initial Italy intelligence sync for ${dateCet} CET.`);
      await runIngestion('catchup');
      return;
    }

    if (!hasToday && hourCet >= 8) {
      const trigger = hourCet === 8 && reason === 'interval' ? 'scheduled_8am_cet' : 'catchup';
      console.log(`[scheduler] Triggering ${trigger} daily sync for ${dateCet} CET (Europe/Rome hour=${hourCet}).`);
      await runIngestion(trigger);
    }
  };

  // Defer initial catch-up check so HTTP/Vite readiness probes succeed immediately on boot
  setTimeout(() => {
    void checkAndTrigger('startup').catch((err) => {
      console.error('[scheduler] Startup check failed:', err);
    });
  }, 10_000);

  // Check every 60 seconds for 8:00 AM CET window or missed daily catch-up
  setInterval(() => {
    void checkAndTrigger('interval').catch((err) => {
      console.error('[scheduler] Interval check failed:', err);
    });
  }, 60 * 1000);
}
