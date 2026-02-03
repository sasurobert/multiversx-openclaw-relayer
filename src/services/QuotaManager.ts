import Database from "better-sqlite3";

export const QUOTA_RESET_INTERVAL_MS = 24 * 60 * 60 * 1000; // 24 hours

export class QuotaManager {
    private db: Database.Database;
    private readonly limit: number;

    constructor(dbPath: string = ":memory:", limit: number = 10) {
        this.db = new Database(dbPath);
        this.limit = limit;
        this.init();
    }

    private init() {
        this.db.exec(`
            CREATE TABLE IF NOT EXISTS quotas (
                address TEXT PRIMARY KEY,
                count INTEGER DEFAULT 0,
                last_reset INTEGER
            )
        `);
    }

    checkLimit(address: string): boolean {
        const now = Date.now();
        const row = this.db.prepare("SELECT count, last_reset FROM quotas WHERE address = ?").get(address) as any;

        if (!row) return true;

        // Reset if 24 hours passed (86400000 ms)
        if (now - row.last_reset > QUOTA_RESET_INTERVAL_MS) {
            this.db.prepare("UPDATE quotas SET count = 0, last_reset = ? WHERE address = ?").run(now, address);
            return true;
        }

        return row.count < this.limit;
    }

    incrementUsage(address: string): void {
        const now = Date.now();
        const row = this.db.prepare("SELECT count FROM quotas WHERE address = ?").get(address);

        if (!row) {
            this.db.prepare("INSERT INTO quotas (address, count, last_reset) VALUES (?, 1, ?)").run(address, now);
        } else {
            this.db.prepare("UPDATE quotas SET count = count + 1 WHERE address = ?").run(address);
        }
    }
}
