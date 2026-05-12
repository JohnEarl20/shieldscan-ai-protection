from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import shutil
import uuid

from .config import ProtectionConfig, ensure_state
from .logging_utils import append_event, utc_now
from .scanner import ScanResult


@dataclass
class QuarantineItem:
    item_id: str
    original_path: Path
    stored_path: Path
    metadata_path: Path
    created_at: str
    sha256: str | None
    score: int
    level: str

    def to_dict(self) -> dict[str, object]:
        return {
            "item_id": self.item_id,
            "original_path": str(self.original_path),
            "stored_path": str(self.stored_path),
            "metadata_path": str(self.metadata_path),
            "created_at": self.created_at,
            "sha256": self.sha256,
            "score": self.score,
            "level": self.level,
        }


class QuarantineManager:
    def __init__(self, config: ProtectionConfig) -> None:
        self.config = config
        ensure_state(config)

    def quarantine(self, result: ScanResult) -> QuarantineItem:
        if not result.path.exists() or not result.path.is_file():
            raise FileNotFoundError(f"Cannot quarantine missing file: {result.path}")

        item_id = uuid.uuid4().hex
        safe_name = _safe_name(result.path.name)
        stored_path = self.config.quarantine_dir / f"{item_id}_{safe_name}.quarantine"
        metadata_path = self.config.quarantine_dir / f"{item_id}.json"
        created_at = utc_now()

        shutil.move(str(result.path), str(stored_path))
        item = QuarantineItem(
            item_id=item_id,
            original_path=result.path,
            stored_path=stored_path,
            metadata_path=metadata_path,
            created_at=created_at,
            sha256=result.sha256,
            score=result.score,
            level=result.level,
        )
        metadata = item.to_dict()
        metadata["findings"] = [finding.__dict__ for finding in result.findings]
        metadata_path.write_text(json.dumps(metadata, indent=2, sort_keys=True), encoding="utf-8")
        append_event(self.config.log_file, "quarantine", metadata)
        return item

    def list_items(self) -> list[QuarantineItem]:
        items: list[QuarantineItem] = []
        for metadata_path in sorted(self.config.quarantine_dir.glob("*.json")):
            try:
                data = json.loads(metadata_path.read_text(encoding="utf-8"))
                items.append(_item_from_metadata(data, metadata_path))
            except (OSError, ValueError, KeyError):
                continue
        return items

    def restore(self, item_id: str, destination: Path | None = None, overwrite: bool = False) -> Path:
        item = self.get(item_id)
        target = destination.expanduser().resolve() if destination else item.original_path
        if target.exists() and not overwrite:
            raise FileExistsError(f"Restore target already exists: {target}")

        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(item.stored_path), str(target))
        try:
            item.metadata_path.unlink()
        except OSError:
            pass
        append_event(
            self.config.log_file,
            "restore",
            {
                "item_id": item_id,
                "restored_to": str(target),
                "original_path": str(item.original_path),
            },
        )
        return target

    def get(self, item_id: str) -> QuarantineItem:
        metadata_path = self.config.quarantine_dir / f"{item_id}.json"
        if not metadata_path.exists():
            raise FileNotFoundError(f"Quarantine item not found: {item_id}")
        data = json.loads(metadata_path.read_text(encoding="utf-8"))
        return _item_from_metadata(data, metadata_path)


def _item_from_metadata(data: dict[str, object], metadata_path: Path) -> QuarantineItem:
    return QuarantineItem(
        item_id=str(data.get("item_id", "unknown")),
        original_path=Path(str(data.get("original_path", ""))),
        stored_path=Path(str(data.get("stored_path", ""))),
        metadata_path=metadata_path,
        created_at=str(data.get("created_at", utc_now())),
        sha256=str(data["sha256"]) if data.get("sha256") else None,
        score=int(data.get("score", 0)),
        level=str(data.get("level", "unknown")),
    )


def _safe_name(name: str) -> str:
    return "".join(char if char.isalnum() or char in "._-" else "_" for char in name)[:120]
