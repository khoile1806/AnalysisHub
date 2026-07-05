#!/usr/bin/env bash
# Backup AnalysisHub state: PostgreSQL (cases, jobs, config), the storage volume
# (uploads/evidence/artifacts) and the Elasticsearch data (ingested logs).
#
# Usage:  scripts/backup.sh [OUT_DIR]
#   OUT_DIR defaults to ./backups/<timestamp>
#
# Restore notes are printed at the end. Run from the repo root.
set -euo pipefail

OUT_DIR="${1:-backups/$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$OUT_DIR"

PG_USER="${POSTGRES_USER:-forensic}"
PG_DB="${POSTGRES_DB:-analysishub}"

echo "==> PostgreSQL dump"
docker compose exec -T postgres pg_dump -U "$PG_USER" "$PG_DB" | gzip > "$OUT_DIR/postgres.sql.gz"

echo "==> storage volume (uploads / evidence / artifacts)"
docker run --rm -v analysishub_storage_data:/data -v "$(pwd)/$OUT_DIR":/backup alpine \
  tar czf /backup/storage_data.tgz -C /data .

echo "==> Elasticsearch data (ingested logs)"
# Cold copy for a consistent snapshot: stop ES, tar the volume, start it again.
# (For a live/incremental backup, configure an ES snapshot repository instead.)
docker compose stop elasticsearch
docker run --rm -v analysishub_elasticsearch_data:/data -v "$(pwd)/$OUT_DIR":/backup alpine \
  tar czf /backup/elasticsearch_data.tgz -C /data .
docker compose start elasticsearch

echo
echo "Backup written to: $OUT_DIR"
echo
echo "Restore:"
echo "  # PostgreSQL"
echo "  gunzip -c $OUT_DIR/postgres.sql.gz | docker compose exec -T postgres psql -U $PG_USER $PG_DB"
echo "  # storage volume"
echo "  docker run --rm -v analysishub_storage_data:/data -v \$(pwd)/$OUT_DIR:/backup alpine sh -c 'rm -rf /data/* && tar xzf /backup/storage_data.tgz -C /data'"
echo "  # Elasticsearch (stop ES first)"
echo "  docker compose stop elasticsearch"
echo "  docker run --rm -v analysishub_elasticsearch_data:/data -v \$(pwd)/$OUT_DIR:/backup alpine sh -c 'rm -rf /data/* && tar xzf /backup/elasticsearch_data.tgz -C /data'"
echo "  docker compose start elasticsearch"
