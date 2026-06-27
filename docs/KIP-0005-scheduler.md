# KIP-0005: Scheduler

The scheduler model supports `max_speed`, `balanced`, `interactive_first`, and `bulk_first`.

Scheduling controls batch size, flush interval, max in-flight frames, and priority mode. The v0 scheduler exposes deterministic planning functions for tests and avoids real sleeps in unit tests.

Tradeoffs:

- `max_speed` flushes as early as possible.
- `balanced` batches more data before flushes.
- `interactive_first` prioritizes small interactive frames.
- `bulk_first` favors larger frames.

The frame layer uses scheduler limits for fragmentation decisions. Benchmarks measure scheduler planning overhead and local round-trip behavior, but do not claim real-world speed.
