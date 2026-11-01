"""Attack-stage relationship model."""

from dataclasses import dataclass


DEFAULT_STAGE_ORDER = [
    "RECON",
    "SERVICE_DISCOVERY",
    "CREDENTIAL_ATTACK",
    "EXPLOITATION",
]


@dataclass(frozen=True)
class StageGraph:
    stages: tuple[str, ...] = tuple(DEFAULT_STAGE_ORDER)

    def intermediate_stages(self, before: str | None, after: str | None) -> list[str]:
        if not before or not after:
            return []
        try:
            i = self.stages.index(before)
            j = self.stages.index(after)
        except ValueError:
            return []
        if j <= i + 1:
            return []
        return list(self.stages[i + 1:j])

    def transition_score(self, before: str | None, after: str | None) -> float:
        if not before or not after:
            return 0.35
        if before == after:
            return 0.30
        try:
            i = self.stages.index(before)
            j = self.stages.index(after)
        except ValueError:
            return 0.20
        distance = j - i
        if distance == 1:
            return 1.0
        if distance > 1:
            return max(0.55, 1.0 - 0.15 * (distance - 1))
        return 0.10
