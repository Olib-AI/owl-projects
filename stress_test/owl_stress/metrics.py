"""Metrics collection and aggregation for stress test results."""

import statistics
from dataclasses import dataclass, field


@dataclass
class StepResult:
    """Result of a single flow step execution."""
    step_index: int
    tool_name: str
    success: bool
    duration_ms: float
    error: str = ""


@dataclass
class FlowResult:
    """Result of a single flow execution (one browser session)."""
    flow_id: int
    batch_size: int
    success: bool
    total_duration_ms: float
    steps: list[StepResult] = field(default_factory=list)
    error: str = ""
    context_id: str = ""


@dataclass
class BatchResult:
    """Aggregated result for a single batch (e.g., all 10 concurrent runs)."""
    batch_size: int
    flow_results: list[FlowResult] = field(default_factory=list)
    start_time: float = 0.0
    end_time: float = 0.0

    @property
    def wall_time_ms(self) -> float:
        return (self.end_time - self.start_time) * 1000

    @property
    def total_flows(self) -> int:
        return len(self.flow_results)

    @property
    def successful_flows(self) -> int:
        return sum(1 for r in self.flow_results if r.success)

    @property
    def failed_flows(self) -> int:
        return self.total_flows - self.successful_flows

    @property
    def success_rate(self) -> float:
        if not self.total_flows:
            return 0.0
        return self.successful_flows / self.total_flows * 100

    @property
    def durations_ms(self) -> list[float]:
        return [r.total_duration_ms for r in self.flow_results if r.success]

    @property
    def avg_duration_ms(self) -> float:
        d = self.durations_ms
        return statistics.mean(d) if d else 0.0

    @property
    def median_duration_ms(self) -> float:
        d = self.durations_ms
        return statistics.median(d) if d else 0.0

    @property
    def p95_duration_ms(self) -> float:
        d = sorted(self.durations_ms)
        if not d:
            return 0.0
        idx = int(len(d) * 0.95)
        return d[min(idx, len(d) - 1)]

    @property
    def p99_duration_ms(self) -> float:
        d = sorted(self.durations_ms)
        if not d:
            return 0.0
        idx = int(len(d) * 0.99)
        return d[min(idx, len(d) - 1)]

    @property
    def min_duration_ms(self) -> float:
        d = self.durations_ms
        return min(d) if d else 0.0

    @property
    def max_duration_ms(self) -> float:
        d = self.durations_ms
        return max(d) if d else 0.0

    @property
    def std_dev_ms(self) -> float:
        d = self.durations_ms
        return statistics.stdev(d) if len(d) > 1 else 0.0


@dataclass
class StressTestResult:
    """Complete result of a full stress test (all batches)."""
    target_name: str
    target_url: str
    flow_name: str
    batch_results: list[BatchResult] = field(default_factory=list)
    start_time: float = 0.0
    end_time: float = 0.0

    @property
    def total_wall_time_s(self) -> float:
        return self.end_time - self.start_time

    @property
    def total_flows_executed(self) -> int:
        return sum(b.total_flows for b in self.batch_results)

    @property
    def total_successful(self) -> int:
        return sum(b.successful_flows for b in self.batch_results)

    @property
    def total_failed(self) -> int:
        return sum(b.failed_flows for b in self.batch_results)

    @property
    def overall_success_rate(self) -> float:
        total = self.total_flows_executed
        if not total:
            return 0.0
        return self.total_successful / total * 100

    def get_step_breakdown(self) -> dict[str, dict]:
        """Get per-step performance breakdown across all batches."""
        step_data: dict[str, list[float]] = {}
        step_failures: dict[str, int] = {}
        step_total: dict[str, int] = {}

        for batch in self.batch_results:
            for flow in batch.flow_results:
                for step in flow.steps:
                    name = step.tool_name
                    step_total[name] = step_total.get(name, 0) + 1
                    if step.success:
                        step_data.setdefault(name, []).append(step.duration_ms)
                    else:
                        step_failures[name] = step_failures.get(name, 0) + 1

        breakdown = {}
        for name in step_total:
            durations = step_data.get(name, [])
            breakdown[name] = {
                "total": step_total[name],
                "failures": step_failures.get(name, 0),
                "avg_ms": statistics.mean(durations) if durations else 0,
                "median_ms": statistics.median(durations) if durations else 0,
                "p95_ms": sorted(durations)[int(len(durations) * 0.95)] if durations else 0,
                "max_ms": max(durations) if durations else 0,
            }

        return breakdown


