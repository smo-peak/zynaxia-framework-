"""
Tests unitaires LOT 9: Observability - Tracing & OpenTelemetry.

Tests des invariants:
- OBS_004: Traces exportées format OpenTelemetry
- OBS_005: Retention traces 30 jours minimum
- OBS_006: Latence chaque span mesurée et stockée
- OBS_007: Erreurs tracées avec stack trace complet
"""

import time
from datetime import datetime, timedelta, timezone
from typing import List
from unittest.mock import MagicMock

import pytest

from src.observability import (
    CorrelationManager,
    ISpanExporter,
    ITraceStore,
    InMemoryTraceStore,
    OpenTelemetryExport,
    Span,
    SpanAlreadyEndedError,
    SpanEvent,
    SpanNotFoundError,
    SpanStatus,
    TraceRetentionPolicy,
    TracingManager,
    trace_span,
)


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def correlation_manager() -> CorrelationManager:
    """Fixture pour CorrelationManager."""
    manager = CorrelationManager()
    manager.clear_all_contexts()
    return manager


@pytest.fixture
def tracing_manager(correlation_manager: CorrelationManager) -> TracingManager:
    """Fixture pour TracingManager."""
    manager = TracingManager(
        correlation_manager=correlation_manager,
        service_name="test-service",
    )
    yield manager
    manager.clear()
    correlation_manager.clear_all_contexts()


@pytest.fixture
def mock_exporter() -> ISpanExporter:
    """Fixture pour mock exporter."""

    class MockExporter(ISpanExporter):
        def __init__(self) -> None:
            self.exported_spans: List[Span] = []
            self.export_called = False

        def export(self, spans: List[Span]) -> bool:
            self.export_called = True
            self.exported_spans.extend(spans)
            return True

    return MockExporter()


# ============================================================================
# Tests OBS_004: Export OpenTelemetry Format
# ============================================================================


class TestOBS004OpenTelemetryExport:
    """Tests invariant OBS_004: Traces exportées format OpenTelemetry."""

    def test_OBS_004_export_returns_opentelemetry_format(
        self, tracing_manager: TracingManager
    ) -> None:
        """OBS_004: Export retourne OpenTelemetryExport."""
        span = tracing_manager.start_span("test-span")
        tracing_manager.end_span(span.span_id)

        export = tracing_manager.export_to_opentelemetry()

        assert isinstance(export, OpenTelemetryExport)
        assert export.schema_url == "https://opentelemetry.io/schemas/1.21.0"

    def test_OBS_004_export_contains_resource_spans(
        self, tracing_manager: TracingManager
    ) -> None:
        """OBS_004: Export contient resource_spans."""
        span = tracing_manager.start_span("test-span")
        tracing_manager.end_span(span.span_id)

        export = tracing_manager.export_to_opentelemetry()

        assert isinstance(export.resource_spans, list)
        assert len(export.resource_spans) > 0

    def test_OBS_004_resource_span_has_service_name(
        self, tracing_manager: TracingManager
    ) -> None:
        """OBS_004: Resource span contient service.name."""
        span = tracing_manager.start_span("test-span")
        tracing_manager.end_span(span.span_id)

        export = tracing_manager.export_to_opentelemetry()

        resource_span = export.resource_spans[0]
        assert "resource" in resource_span
        assert "attributes" in resource_span["resource"]

        service_attr = None
        for attr in resource_span["resource"]["attributes"]:
            if attr["key"] == "service.name":
                service_attr = attr
                break

        assert service_attr is not None
        assert service_attr["value"]["stringValue"] == "test-service"

    def test_OBS_004_span_has_trace_id_and_span_id(
        self, tracing_manager: TracingManager
    ) -> None:
        """OBS_004: Span OTLP contient traceId et spanId."""
        span = tracing_manager.start_span("test-span")
        tracing_manager.end_span(span.span_id)

        export = tracing_manager.export_to_opentelemetry()
        otlp_span = export.resource_spans[0]["scopeSpans"][0]["spans"][0]

        assert "traceId" in otlp_span
        assert "spanId" in otlp_span
        assert len(otlp_span["traceId"]) == 32  # UUID sans tirets
        assert len(otlp_span["spanId"]) == 16

    def test_OBS_004_span_has_timestamps(
        self, tracing_manager: TracingManager
    ) -> None:
        """OBS_004: Span OTLP contient timestamps en nanoseconds."""
        span = tracing_manager.start_span("test-span")
        tracing_manager.end_span(span.span_id)

        export = tracing_manager.export_to_opentelemetry()
        otlp_span = export.resource_spans[0]["scopeSpans"][0]["spans"][0]

        assert "startTimeUnixNano" in otlp_span
        assert "endTimeUnixNano" in otlp_span
        assert int(otlp_span["startTimeUnixNano"]) > 0
        assert int(otlp_span["endTimeUnixNano"]) >= int(otlp_span["startTimeUnixNano"])

    def test_OBS_004_span_includes_correlation_id(
        self, tracing_manager: TracingManager
    ) -> None:
        """OBS_004: Span OTLP inclut correlation_id dans attributs."""
        span = tracing_manager.start_span("test-span")
        tracing_manager.end_span(span.span_id)

        export = tracing_manager.export_to_opentelemetry()
        otlp_span = export.resource_spans[0]["scopeSpans"][0]["spans"][0]

        correlation_attr = None
        for attr in otlp_span["attributes"]:
            if attr["key"] == "correlation_id":
                correlation_attr = attr
                break

        assert correlation_attr is not None
        assert "stringValue" in correlation_attr["value"]

    def test_OBS_004_span_status_mapping(
        self, tracing_manager: TracingManager
    ) -> None:
        """OBS_004: Status mappé correctement en code OTLP."""
        # Test OK status
        span1 = tracing_manager.start_span("span-ok")
        tracing_manager.end_span(span1.span_id)

        # Test ERROR status
        span2 = tracing_manager.start_span("span-error")
        tracing_manager.record_error(span2.span_id, ValueError("test error"))
        tracing_manager.end_span(span2.span_id)

        export = tracing_manager.export_to_opentelemetry()
        spans = export.resource_spans[0]["scopeSpans"][0]["spans"]

        # Find spans by name
        ok_span = next(s for s in spans if s["name"] == "span-ok")
        error_span = next(s for s in spans if s["name"] == "span-error")

        assert ok_span["status"]["code"] == 1  # OK
        assert error_span["status"]["code"] == 2  # ERROR

    def test_OBS_004_span_events_exported(
        self, tracing_manager: TracingManager
    ) -> None:
        """OBS_004: Events du span exportés."""
        span = tracing_manager.start_span("test-span")
        tracing_manager.add_event(span.span_id, "test-event", {"key": "value"})
        tracing_manager.end_span(span.span_id)

        export = tracing_manager.export_to_opentelemetry()
        otlp_span = export.resource_spans[0]["scopeSpans"][0]["spans"][0]

        assert "events" in otlp_span
        assert len(otlp_span["events"]) == 1
        assert otlp_span["events"][0]["name"] == "test-event"

    def test_OBS_004_parent_span_id_exported(
        self, tracing_manager: TracingManager
    ) -> None:
        """OBS_004: parentSpanId exporté si présent."""
        parent = tracing_manager.start_span("parent")
        child = tracing_manager.start_span("child", parent_span_id=parent.span_id)
        tracing_manager.end_span(child.span_id)
        tracing_manager.end_span(parent.span_id)

        export = tracing_manager.export_to_opentelemetry()
        spans = export.resource_spans[0]["scopeSpans"][0]["spans"]

        child_otlp = next(s for s in spans if s["name"] == "child")
        assert "parentSpanId" in child_otlp

    def test_OBS_004_attributes_exported_with_correct_types(
        self, tracing_manager: TracingManager
    ) -> None:
        """OBS_004: Attributs exportés avec types corrects."""
        span = tracing_manager.start_span(
            "test-span",
            attributes={
                "string_attr": "value",
                "int_attr": 42,
                "float_attr": 3.14,
                "bool_attr": True,
            },
        )
        tracing_manager.end_span(span.span_id)

        export = tracing_manager.export_to_opentelemetry()
        otlp_span = export.resource_spans[0]["scopeSpans"][0]["spans"][0]

        attrs = {a["key"]: a["value"] for a in otlp_span["attributes"]}

        assert "stringValue" in attrs["string_attr"]
        assert "intValue" in attrs["int_attr"]
        assert "doubleValue" in attrs["float_attr"]
        assert "boolValue" in attrs["bool_attr"]


# ============================================================================
# Tests OBS_005: Retention 30 jours
# ============================================================================


class TestOBS005Retention:
    """Tests invariant OBS_005: Retention traces 30 jours minimum."""

    def test_OBS_005_default_retention_is_30_days(
        self, tracing_manager: TracingManager
    ) -> None:
        """OBS_005: Retention par défaut est 30 jours."""
        assert tracing_manager.DEFAULT_RETENTION_DAYS == 30

    def test_OBS_005_retention_policy_default_30_days(self) -> None:
        """OBS_005: TraceRetentionPolicy défaut 30 jours."""
        policy = TraceRetentionPolicy()
        assert policy.retention_days == 30

    def test_OBS_005_cleanup_removes_expired_spans(
        self, tracing_manager: TracingManager
    ) -> None:
        """OBS_005: cleanup_old_spans supprime spans > 30 jours."""
        # Créer span et le terminer
        span = tracing_manager.start_span("old-span")
        tracing_manager.end_span(span.span_id)

        # Simuler span ancien en modifiant start_time
        completed = tracing_manager.get_completed_spans()[0]
        old_time = datetime.now(timezone.utc) - timedelta(days=35)
        # Créer nouveau span avec date ancienne
        tracing_manager._completed_spans[0] = Span(
            span_id=completed.span_id,
            trace_id=completed.trace_id,
            correlation_id=completed.correlation_id,
            name=completed.name,
            service_name=completed.service_name,
            start_time=old_time,
            end_time=old_time + timedelta(seconds=1),
            duration_ms=1000,
            status=SpanStatus.OK,
        )

        removed = tracing_manager.cleanup_old_spans()

        assert removed >= 1
        assert len(tracing_manager.get_completed_spans()) == 0

    def test_OBS_005_cleanup_keeps_recent_spans(
        self, tracing_manager: TracingManager
    ) -> None:
        """OBS_005: cleanup garde spans < 30 jours."""
        span = tracing_manager.start_span("recent-span")
        tracing_manager.end_span(span.span_id)

        removed = tracing_manager.cleanup_old_spans()

        assert removed == 0
        assert len(tracing_manager.get_completed_spans()) == 1

    def test_OBS_005_is_span_expired_true_for_old(
        self, tracing_manager: TracingManager
    ) -> None:
        """OBS_005: is_span_expired retourne True pour span > 30 jours."""
        old_span = Span(
            span_id="test-id",
            trace_id="trace-id",
            correlation_id="corr-id",
            name="old-span",
            service_name="test",
            start_time=datetime.now(timezone.utc) - timedelta(days=31),
        )

        assert tracing_manager.is_span_expired(old_span) is True

    def test_OBS_005_is_span_expired_false_for_recent(
        self, tracing_manager: TracingManager
    ) -> None:
        """OBS_005: is_span_expired retourne False pour span < 30 jours."""
        recent_span = Span(
            span_id="test-id",
            trace_id="trace-id",
            correlation_id="corr-id",
            name="recent-span",
            service_name="test",
            start_time=datetime.now(timezone.utc) - timedelta(days=29),
        )

        assert tracing_manager.is_span_expired(recent_span) is False

    def test_OBS_005_set_retention_policy_rejects_under_30(
        self, tracing_manager: TracingManager
    ) -> None:
        """OBS_005: set_retention_policy rejette < 30 jours."""
        policy = TraceRetentionPolicy(retention_days=20)

        with pytest.raises(ValueError, match="retention_days must be >= 30"):
            tracing_manager.set_retention_policy(policy)

    def test_OBS_005_cleanup_enforces_minimum_30_days(
        self, tracing_manager: TracingManager
    ) -> None:
        """OBS_005: cleanup_old_spans applique minimum 30 jours même si moins demandé."""
        # Créer span de 25 jours
        span = tracing_manager.start_span("span-25-days")
        tracing_manager.end_span(span.span_id)

        # Modifier date
        completed = tracing_manager.get_completed_spans()[0]
        tracing_manager._completed_spans[0] = Span(
            span_id=completed.span_id,
            trace_id=completed.trace_id,
            correlation_id=completed.correlation_id,
            name=completed.name,
            service_name=completed.service_name,
            start_time=datetime.now(timezone.utc) - timedelta(days=25),
            end_time=datetime.now(timezone.utc) - timedelta(days=25),
            status=SpanStatus.OK,
        )

        # Demander cleanup avec 10 jours (doit être ignoré, min 30)
        removed = tracing_manager.cleanup_old_spans(retention_days=10)

        # Span de 25 jours doit être conservé (min 30 jours appliqué)
        assert removed == 0
        assert len(tracing_manager.get_completed_spans()) == 1


# ============================================================================
# Tests OBS_006: Latence spans mesurée
# ============================================================================


class TestOBS006LatencyMeasurement:
    """Tests invariant OBS_006: Latence chaque span mesurée et stockée."""

    def test_OBS_006_span_has_duration_after_end(
        self, tracing_manager: TracingManager
    ) -> None:
        """OBS_006: Span a duration_ms après end_span."""
        span = tracing_manager.start_span("test-span")
        tracing_manager.end_span(span.span_id)

        ended_span = tracing_manager.get_span(span.span_id)

        assert ended_span is not None
        assert ended_span.duration_ms is not None
        assert ended_span.duration_ms >= 0

    def test_OBS_006_duration_reflects_actual_time(
        self, tracing_manager: TracingManager
    ) -> None:
        """OBS_006: duration_ms reflète temps réel écoulé."""
        span = tracing_manager.start_span("test-span")

        time.sleep(0.05)  # 50ms

        tracing_manager.end_span(span.span_id)
        ended_span = tracing_manager.get_span(span.span_id)

        # Doit être au moins 50ms (avec tolérance)
        assert ended_span is not None
        assert ended_span.duration_ms is not None
        assert ended_span.duration_ms >= 45  # Tolérance
        assert ended_span.duration_ms < 200  # Pas trop long

    def test_OBS_006_span_has_start_and_end_time(
        self, tracing_manager: TracingManager
    ) -> None:
        """OBS_006: Span a start_time et end_time."""
        span = tracing_manager.start_span("test-span")
        assert span.start_time is not None
        assert span.end_time is None

        tracing_manager.end_span(span.span_id)
        ended_span = tracing_manager.get_span(span.span_id)

        assert ended_span is not None
        assert ended_span.end_time is not None
        assert ended_span.end_time >= ended_span.start_time

    def test_OBS_006_duration_exported_in_otlp(
        self, tracing_manager: TracingManager
    ) -> None:
        """OBS_006: duration_ms exporté dans format OTLP."""
        span = tracing_manager.start_span("test-span")
        time.sleep(0.01)
        tracing_manager.end_span(span.span_id)

        export = tracing_manager.export_to_opentelemetry()
        otlp_span = export.resource_spans[0]["scopeSpans"][0]["spans"][0]

        # Chercher duration_ms dans attributs
        duration_attr = None
        for attr in otlp_span["attributes"]:
            if attr["key"] == "duration_ms":
                duration_attr = attr
                break

        assert duration_attr is not None
        assert "doubleValue" in duration_attr["value"]
        assert duration_attr["value"]["doubleValue"] >= 0

    def test_OBS_006_multiple_spans_independent_duration(
        self, tracing_manager: TracingManager
    ) -> None:
        """OBS_006: Plusieurs spans ont durées indépendantes."""
        span1 = tracing_manager.start_span("span-1")
        time.sleep(0.02)

        span2 = tracing_manager.start_span("span-2")
        time.sleep(0.01)

        tracing_manager.end_span(span2.span_id)
        time.sleep(0.01)
        tracing_manager.end_span(span1.span_id)

        ended1 = tracing_manager.get_span(span1.span_id)
        ended2 = tracing_manager.get_span(span2.span_id)

        assert ended1 is not None and ended2 is not None
        assert ended1.duration_ms is not None and ended2.duration_ms is not None
        # span1 doit avoir durée > span2
        assert ended1.duration_ms > ended2.duration_ms

    def test_OBS_006_perf_counter_for_precision(
        self, tracing_manager: TracingManager
    ) -> None:
        """OBS_006: Utilise perf_counter pour précision."""
        span = tracing_manager.start_span("test-span")

        # Vérifier que _start_perf_counter est défini
        assert span._start_perf_counter is not None
        assert isinstance(span._start_perf_counter, float)

    def test_OBS_006_nested_spans_independent_latency(
        self, tracing_manager: TracingManager
    ) -> None:
        """OBS_006: Spans imbriqués ont latences indépendantes."""
        parent = tracing_manager.start_span("parent")
        time.sleep(0.01)

        child = tracing_manager.start_span("child", parent_span_id=parent.span_id)
        time.sleep(0.02)
        tracing_manager.end_span(child.span_id)

        time.sleep(0.01)
        tracing_manager.end_span(parent.span_id)

        ended_parent = tracing_manager.get_span(parent.span_id)
        ended_child = tracing_manager.get_span(child.span_id)

        assert ended_parent is not None and ended_child is not None
        assert ended_parent.duration_ms is not None
        assert ended_child.duration_ms is not None
        # Parent doit avoir durée > enfant
        assert ended_parent.duration_ms > ended_child.duration_ms

    def test_OBS_006_context_manager_measures_latency(
        self, tracing_manager: TracingManager
    ) -> None:
        """OBS_006: Context manager mesure latence automatiquement."""
        with trace_span(tracing_manager, "ctx-span") as span:
            time.sleep(0.02)

        ended = tracing_manager.get_span(span.span_id)

        assert ended is not None
        assert ended.duration_ms is not None
        assert ended.duration_ms >= 15  # Tolérance

    def test_OBS_006_very_short_span_still_measured(
        self, tracing_manager: TracingManager
    ) -> None:
        """OBS_006: Span très court est quand même mesuré."""
        span = tracing_manager.start_span("quick-span")
        tracing_manager.end_span(span.span_id)

        ended = tracing_manager.get_span(span.span_id)

        assert ended is not None
        assert ended.duration_ms is not None
        assert ended.duration_ms >= 0

    def test_OBS_006_duration_precision_submillisecond(
        self, tracing_manager: TracingManager
    ) -> None:
        """OBS_006: Précision sub-milliseconde possible."""
        span = tracing_manager.start_span("precision-span")
        tracing_manager.end_span(span.span_id)

        ended = tracing_manager.get_span(span.span_id)

        assert ended is not None
        assert ended.duration_ms is not None
        # Peut avoir décimales
        assert isinstance(ended.duration_ms, float)


# ============================================================================
# Tests OBS_007: Stack trace erreurs
# ============================================================================


class TestOBS007ErrorStackTrace:
    """Tests invariant OBS_007: Erreurs tracées avec stack trace complet."""

    def test_OBS_007_record_error_captures_stack_trace(
        self, tracing_manager: TracingManager
    ) -> None:
        """OBS_007: record_error capture stack trace."""
        span = tracing_manager.start_span("error-span")

        try:
            raise ValueError("Test error message")
        except ValueError as e:
            tracing_manager.record_error(span.span_id, e)

        active_span = tracing_manager.get_span(span.span_id)

        assert active_span is not None
        assert active_span.error_stack_trace is not None
        assert "ValueError" in active_span.error_stack_trace
        assert "Test error message" in active_span.error_stack_trace

    def test_OBS_007_stack_trace_includes_traceback(
        self, tracing_manager: TracingManager
    ) -> None:
        """OBS_007: Stack trace inclut traceback complet."""
        span = tracing_manager.start_span("error-span")

        def inner_function() -> None:
            raise RuntimeError("Inner error")

        try:
            inner_function()
        except RuntimeError as e:
            tracing_manager.record_error(span.span_id, e)

        active_span = tracing_manager.get_span(span.span_id)

        assert active_span is not None
        assert active_span.error_stack_trace is not None
        assert "inner_function" in active_span.error_stack_trace
        assert "RuntimeError" in active_span.error_stack_trace

    def test_OBS_007_error_sets_status_error(
        self, tracing_manager: TracingManager
    ) -> None:
        """OBS_007: Erreur définit status ERROR."""
        span = tracing_manager.start_span("error-span")

        try:
            raise Exception("Test")
        except Exception as e:
            tracing_manager.record_error(span.span_id, e)

        active_span = tracing_manager.get_span(span.span_id)

        assert active_span is not None
        assert active_span.status == SpanStatus.ERROR

    def test_OBS_007_error_attributes_recorded(
        self, tracing_manager: TracingManager
    ) -> None:
        """OBS_007: Attributs erreur enregistrés."""
        span = tracing_manager.start_span("error-span")

        try:
            raise TypeError("Type mismatch")
        except TypeError as e:
            tracing_manager.record_error(span.span_id, e)

        active_span = tracing_manager.get_span(span.span_id)

        assert active_span is not None
        assert active_span.attributes["error.type"] == "TypeError"
        assert active_span.attributes["error.message"] == "Type mismatch"

    def test_OBS_007_error_event_added(
        self, tracing_manager: TracingManager
    ) -> None:
        """OBS_007: Event 'exception' ajouté au span."""
        span = tracing_manager.start_span("error-span")

        try:
            raise KeyError("missing_key")
        except KeyError as e:
            tracing_manager.record_error(span.span_id, e)

        active_span = tracing_manager.get_span(span.span_id)

        assert active_span is not None
        assert len(active_span.events) == 1
        assert active_span.events[0].name == "exception"
        assert active_span.events[0].attributes["exception.type"] == "KeyError"

    def test_OBS_007_context_manager_captures_error(
        self, tracing_manager: TracingManager
    ) -> None:
        """OBS_007: Context manager capture erreur automatiquement."""
        with pytest.raises(ValueError):
            with trace_span(tracing_manager, "ctx-error-span") as span:
                raise ValueError("Context error")

        ended = tracing_manager.get_span(span.span_id)

        assert ended is not None
        assert ended.status == SpanStatus.ERROR
        assert ended.error_stack_trace is not None
        assert "ValueError" in ended.error_stack_trace

    def test_OBS_007_nested_exception_full_trace(
        self, tracing_manager: TracingManager
    ) -> None:
        """OBS_007: Exception imbriquée a trace complète."""
        span = tracing_manager.start_span("nested-error")

        def level_1() -> None:
            level_2()

        def level_2() -> None:
            level_3()

        def level_3() -> None:
            raise Exception("Deep error")

        try:
            level_1()
        except Exception as e:
            tracing_manager.record_error(span.span_id, e)

        active_span = tracing_manager.get_span(span.span_id)

        assert active_span is not None
        assert active_span.error_stack_trace is not None
        assert "level_1" in active_span.error_stack_trace
        assert "level_2" in active_span.error_stack_trace
        assert "level_3" in active_span.error_stack_trace

    def test_OBS_007_error_exported_in_otlp(
        self, tracing_manager: TracingManager
    ) -> None:
        """OBS_007: Erreur exportée dans format OTLP."""
        span = tracing_manager.start_span("export-error")

        try:
            raise Exception("Export test")
        except Exception as e:
            tracing_manager.record_error(span.span_id, e)

        tracing_manager.end_span(span.span_id)

        export = tracing_manager.export_to_opentelemetry()
        otlp_span = export.resource_spans[0]["scopeSpans"][0]["spans"][0]

        # Status ERROR
        assert otlp_span["status"]["code"] == 2

        # Event exception
        assert len(otlp_span["events"]) > 0
        exception_event = otlp_span["events"][0]
        assert exception_event["name"] == "exception"

    def test_OBS_007_record_error_without_setting_status(
        self, tracing_manager: TracingManager
    ) -> None:
        """OBS_007: record_error peut ne pas changer status."""
        span = tracing_manager.start_span("error-span")

        try:
            raise Warning("Non-critical")
        except Warning as e:
            tracing_manager.record_error(span.span_id, e, set_status=False)

        active_span = tracing_manager.get_span(span.span_id)

        assert active_span is not None
        assert active_span.status == SpanStatus.UNSET
        assert active_span.error_stack_trace is not None

    def test_OBS_007_multiple_errors_last_stack_trace(
        self, tracing_manager: TracingManager
    ) -> None:
        """OBS_007: Plusieurs erreurs -> dernier stack trace."""
        span = tracing_manager.start_span("multi-error")

        try:
            raise ValueError("First error")
        except ValueError as e:
            tracing_manager.record_error(span.span_id, e)

        try:
            raise TypeError("Second error")
        except TypeError as e:
            tracing_manager.record_error(span.span_id, e)

        active_span = tracing_manager.get_span(span.span_id)

        assert active_span is not None
        assert "TypeError" in active_span.error_stack_trace
        assert len(active_span.events) == 2


# ============================================================================
# Tests Context Manager trace_span
# ============================================================================


class TestTraceSpanContextManager:
    """Tests du context manager trace_span."""

    def test_context_manager_creates_span(
        self, tracing_manager: TracingManager
    ) -> None:
        """Context manager crée un span."""
        with trace_span(tracing_manager, "ctx-span") as span:
            assert span is not None
            assert span.name == "ctx-span"

    def test_context_manager_ends_span(
        self, tracing_manager: TracingManager
    ) -> None:
        """Context manager termine le span."""
        with trace_span(tracing_manager, "ctx-span") as span:
            pass

        ended = tracing_manager.get_span(span.span_id)
        assert ended is not None
        assert ended.end_time is not None
        assert ended.status == SpanStatus.OK

    def test_context_manager_with_attributes(
        self, tracing_manager: TracingManager
    ) -> None:
        """Context manager accepte attributs."""
        with trace_span(tracing_manager, "ctx-span", key="value", count=42) as span:
            pass

        ended = tracing_manager.get_span(span.span_id)
        assert ended is not None
        assert ended.attributes.get("key") == "value"
        assert ended.attributes.get("count") == 42

    def test_context_manager_ends_on_exception(
        self, tracing_manager: TracingManager
    ) -> None:
        """Context manager termine même si exception."""
        with pytest.raises(RuntimeError):
            with trace_span(tracing_manager, "ctx-span") as span:
                raise RuntimeError("Test")

        ended = tracing_manager.get_span(span.span_id)
        assert ended is not None
        assert ended.end_time is not None

    def test_context_manager_propagates_exception(
        self, tracing_manager: TracingManager
    ) -> None:
        """Context manager propage l'exception."""
        with pytest.raises(ValueError, match="Original"):
            with trace_span(tracing_manager, "ctx-span"):
                raise ValueError("Original error")


# ============================================================================
# Tests Span Management
# ============================================================================


class TestSpanManagement:
    """Tests gestion des spans."""

    def test_start_span_returns_span(
        self, tracing_manager: TracingManager
    ) -> None:
        """start_span retourne un Span."""
        span = tracing_manager.start_span("test")
        assert isinstance(span, Span)

    def test_start_span_generates_ids(
        self, tracing_manager: TracingManager
    ) -> None:
        """start_span génère span_id et trace_id."""
        span = tracing_manager.start_span("test")
        assert span.span_id is not None
        assert span.trace_id is not None
        assert len(span.span_id) == 36  # UUID format

    def test_start_span_empty_name_raises(
        self, tracing_manager: TracingManager
    ) -> None:
        """start_span avec nom vide lève ValueError."""
        with pytest.raises(ValueError, match="cannot be empty"):
            tracing_manager.start_span("")

    def test_end_span_not_found_raises(
        self, tracing_manager: TracingManager
    ) -> None:
        """end_span avec ID inconnu lève SpanNotFoundError."""
        with pytest.raises(SpanNotFoundError):
            tracing_manager.end_span("unknown-id")

    def test_end_span_twice_raises(
        self, tracing_manager: TracingManager
    ) -> None:
        """end_span deux fois lève SpanAlreadyEndedError."""
        span = tracing_manager.start_span("test")
        tracing_manager.end_span(span.span_id)

        with pytest.raises(SpanAlreadyEndedError):
            tracing_manager.end_span(span.span_id)

    def test_add_event_to_span(
        self, tracing_manager: TracingManager
    ) -> None:
        """add_event ajoute événement au span."""
        span = tracing_manager.start_span("test")
        tracing_manager.add_event(span.span_id, "test-event", {"key": "value"})

        assert len(span.events) == 1
        assert span.events[0].name == "test-event"

    def test_add_event_empty_name_raises(
        self, tracing_manager: TracingManager
    ) -> None:
        """add_event avec nom vide lève ValueError."""
        span = tracing_manager.start_span("test")

        with pytest.raises(ValueError, match="cannot be empty"):
            tracing_manager.add_event(span.span_id, "")

    def test_set_attribute_on_span(
        self, tracing_manager: TracingManager
    ) -> None:
        """set_attribute définit attribut."""
        span = tracing_manager.start_span("test")
        tracing_manager.set_attribute(span.span_id, "custom", "value")

        assert span.attributes["custom"] == "value"

    def test_get_span_active(
        self, tracing_manager: TracingManager
    ) -> None:
        """get_span trouve span actif."""
        span = tracing_manager.start_span("test")
        found = tracing_manager.get_span(span.span_id)

        assert found is span

    def test_get_span_completed(
        self, tracing_manager: TracingManager
    ) -> None:
        """get_span trouve span terminé."""
        span = tracing_manager.start_span("test")
        tracing_manager.end_span(span.span_id)

        found = tracing_manager.get_span(span.span_id)
        assert found is not None
        assert found.span_id == span.span_id

    def test_get_trace_returns_all_spans(
        self, tracing_manager: TracingManager
    ) -> None:
        """get_trace retourne tous spans d'une trace."""
        span1 = tracing_manager.start_span("span-1")
        span2 = tracing_manager.start_span("span-2", trace_id=span1.trace_id)

        trace = tracing_manager.get_trace(span1.trace_id)

        assert len(trace) == 2

    def test_child_span_inherits_trace_id(
        self, tracing_manager: TracingManager
    ) -> None:
        """Span enfant hérite trace_id du parent."""
        parent = tracing_manager.start_span("parent")
        child = tracing_manager.start_span("child", parent_span_id=parent.span_id)

        assert child.trace_id == parent.trace_id
        assert child.parent_span_id == parent.span_id


# ============================================================================
# Tests Interfaces & Dataclasses
# ============================================================================


class TestInterfacesAndDataclasses:
    """Tests interfaces et dataclasses."""

    def test_span_status_enum_values(self) -> None:
        """SpanStatus a valeurs OK, ERROR, UNSET."""
        assert SpanStatus.OK.value == "ok"
        assert SpanStatus.ERROR.value == "error"
        assert SpanStatus.UNSET.value == "unset"

    def test_span_event_creation(self) -> None:
        """SpanEvent peut être créé."""
        event = SpanEvent(
            name="test",
            timestamp=datetime.now(timezone.utc),
            attributes={"key": "value"},
        )
        assert event.name == "test"

    def test_trace_retention_policy_defaults(self) -> None:
        """TraceRetentionPolicy a valeurs par défaut."""
        policy = TraceRetentionPolicy()
        assert policy.retention_days == 30
        assert policy.max_spans_per_trace == 1000
        assert policy.archive_after_days == 7

    def test_opentelemetry_export_schema_url(self) -> None:
        """OpenTelemetryExport a schema_url par défaut."""
        export = OpenTelemetryExport(resource_spans=[])
        assert "opentelemetry.io" in export.schema_url

    def test_in_memory_store_implements_interface(self) -> None:
        """InMemoryTraceStore implémente ITraceStore."""
        store = InMemoryTraceStore()
        assert isinstance(store, ITraceStore)

    def test_in_memory_store_operations(self) -> None:
        """InMemoryTraceStore opérations de base."""
        store = InMemoryTraceStore()

        span = Span(
            span_id="span-1",
            trace_id="trace-1",
            correlation_id="corr-1",
            name="test",
            service_name="test",
            start_time=datetime.now(timezone.utc),
        )

        store.store(span)
        spans = store.get_by_trace_id("trace-1")

        assert len(spans) == 1
        assert spans[0].span_id == "span-1"

    def test_tracing_manager_custom_service_name(
        self, correlation_manager: CorrelationManager
    ) -> None:
        """TracingManager accepte service_name personnalisé."""
        manager = TracingManager(
            correlation_manager=correlation_manager,
            service_name="custom-service",
        )
        span = manager.start_span("test")

        assert span.service_name == "custom-service"


# ============================================================================
# Tests Exceptions
# ============================================================================


class TestExceptions:
    """Tests des exceptions."""

    def test_span_not_found_error(self) -> None:
        """SpanNotFoundError peut être levée."""
        with pytest.raises(SpanNotFoundError):
            raise SpanNotFoundError("Span xyz not found")

    def test_span_already_ended_error(self) -> None:
        """SpanAlreadyEndedError peut être levée."""
        with pytest.raises(SpanAlreadyEndedError):
            raise SpanAlreadyEndedError("Span already ended")

    def test_record_error_span_not_found(
        self, tracing_manager: TracingManager
    ) -> None:
        """record_error avec span inconnu lève SpanNotFoundError."""
        with pytest.raises(SpanNotFoundError):
            tracing_manager.record_error("unknown", ValueError("test"))

    def test_add_event_span_not_found(
        self, tracing_manager: TracingManager
    ) -> None:
        """add_event avec span inconnu lève SpanNotFoundError."""
        with pytest.raises(SpanNotFoundError):
            tracing_manager.add_event("unknown", "event")
