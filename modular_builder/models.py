from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class BuildRow:
    project: str
    cve: str
    file: str
    function: str
    patch_commit: str
    ex_patch_commit: str
    dataset_type: str
    bug_start: str
    bug_end: str
    patch_start: str
    patch_end: str

    @classmethod
    def from_csv_row(cls, row: dict[str, str]) -> "BuildRow":
        def g(key: str) -> str:
            return (row.get(key) or "").strip()

        return cls(
            project=g("Project"),
            cve=g("CVE"),
            file=g("File"),
            function=g("Function"),
            patch_commit=g("Patch commit"),
            ex_patch_commit=g("Ex-patch commit"),
            dataset_type=g("Dataset Type"),
            bug_start=g("Bug start"),
            bug_end=g("Bug end"),
            patch_start=g("Patch start"),
            patch_end=g("Patch end"),
        )

    def commit_refs(self) -> list[tuple[str, str]]:
        refs: list[tuple[str, str]] = []
        if self.patch_commit:
            refs.append(("patch", self.patch_commit))
        if self.ex_patch_commit:
            refs.append(("ex_patch", self.ex_patch_commit))
        return refs

    def has_release_window(self) -> bool:
        return bool(self.bug_start and self.patch_end)

    def release_window(self) -> Optional[tuple[str, str]]:
        if not self.has_release_window():
            return None
        return self.bug_start, self.patch_end
