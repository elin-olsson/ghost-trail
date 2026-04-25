import os
import shutil
import zipfile
import hashlib
import json
from datetime import datetime
from pathlib import Path

class GhostEvidenceCollector:
    def __init__(self, output_dir=None):
        # Default to a folder in the project root if not specified
        if output_dir is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            output_dir = os.path.join(base_dir, "data", "evidence")
            
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _calculate_sha256(self, file_path):
        """Calculates SHA-256 hash of a file for integrity verification."""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception:
            return None

    def collect_artifacts(self, artifact_paths):
        """Copies artifacts to a secure ZIP package and generates a manifest."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        case_id = f"GT_EVIDENCE_{timestamp}"
        temp_work_dir = self.output_dir / case_id
        temp_work_dir.mkdir(exist_ok=True)
        
        manifest = {
            "case_id": case_id,
            "collected_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "files": []
        }

        print(f"  [+] Collecting evidence to {case_id}...")

        for original_path in artifact_paths:
            orig_p = Path(original_path)
            if not orig_p.exists():
                continue

            safe_name = str(orig_p).replace("/", "_").strip("_")
            dest_path = temp_work_dir / safe_name
            
            try:
                original_hash = self._calculate_sha256(original_path)
                shutil.copy2(original_path, dest_path)
                
                manifest["files"].append({
                    "original_path": str(orig_p),
                    "stored_as": safe_name,
                    "sha256": original_hash,
                    "size_bytes": orig_p.stat().st_size
                })
            except Exception as e:
                print(f"  [!] Failed to collect {original_path}: {e}")

        manifest_path = temp_work_dir / "manifest.json"
        with open(manifest_path, "w") as f:
            json.dump(manifest, f, indent=4)

        final_zip_path = self.output_dir / f"{case_id}.zip"
        with zipfile.ZipFile(final_zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for file in temp_work_dir.iterdir():
                zipf.write(file, arcname=file.name)

        shutil.rmtree(temp_work_dir)
        print(f"  [SUCCESS] Evidence package created: {final_zip_path}")
        return final_zip_path

if __name__ == "__main__":
    collector = GhostEvidenceCollector()
    collector.collect_artifacts(["/var/log/wtmp"])
