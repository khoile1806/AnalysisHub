# The watcher as a long-running service.
#
# It exists as its own container rather than a host cron job for one reason: the
# hand-off to the backend is a file, and a file only works if both sides agree on
# where it is. Running here means the path is fixed by compose instead of by
# whatever the operator happened to type into Task Scheduler.
FROM python:3.12-slim

# No compiler needed: typer/rich/pydantic ship wheels for this platform.
ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Dependencies first so a change to the watcher source does not re-resolve them.
COPY tools/plugin-release-watch/pyproject.toml ./
RUN pip install --no-cache-dir "typer>=0.12" "rich>=13.7" "pydantic>=2.6"

COPY tools/plugin-release-watch/watcher ./watcher
COPY tools/plugin-release-watch/watchlist.txt ./watchlist.txt

# Unprivileged: this container only reads a public API and writes one report.
RUN useradd -m -u 10002 watcher && mkdir -p /data/plugin-watch && chown -R watcher:watcher /data
USER watcher

# The report path the backend reads (data/plugin-watch/report.json under its own
# working directory) is the same file through the shared ./backend/data mount.
ENTRYPOINT ["python", "-m", "watcher.cli", "watch"]
CMD ["--json", "/data/plugin-watch/report.json", "--state", "/data/plugin-watch/release-state.json"]
