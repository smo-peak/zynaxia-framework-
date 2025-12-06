"""
LOT 9: Observability - Tracing & OpenTelemetry

Implémente le tracing distribué avec:
- Export format OpenTelemetry (OBS_004)
- Retention traces 30 jours (OBS_005)
- Mesure latence spans (OBS_006)
- Stack trace erreurs (OBS_007)

Invariants:
    OBS_004: Traces exportées format OpenTelemetry
    OBS_005: Retention traces 30 jours minimum
    OBS_006: Latence chaque span mesurée et stockée
    OBS_007: Erreurs tracées avec stack trace complet
"""

import time
import traceback
import uuid
from abc import ABC, abstractmethod
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, Generator, List, Optional

from .interfaces import ICorrelationManager


class SpanStatus(Enum):
    """Statut d'un span."""

    OK = "ok"
    ERROR = "error"
    UNSET = "unset"


@dataclass
class SpanEvent:
    """Événement dans un span."""

    name: str
    timestamp: datetime
    attributes: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Span:
    """
    Représente un span de tracing.

    Invariants:
        OBS_006: duration_ms calculé à la fin du span
        OBS_007: error_stack_trace stocke les erreurs
    """

    span_id: str
    trace_id: str
    correlation_id: str
    name: str
    service_name: str
    start_time: datetime
    end_time: Optional[datetime] = None
    duration_ms: Optional[float] = None  # OBS_006
    status: SpanStatus = SpanStatus.UNSET
    parent_span_id: Optional[str] = None
    attributes: Dict[str, Any] = field(default_factory=dict)
    events: List[SpanEvent] = field(default_factory=list)
    error_stack_trace: Optional[str] = None  # OBS_007
    # Internal timing for precise measurement
    _start_perf_counter: Optional[float] = field(default=None, repr=False)


@dataclass
class OpenTelemetryExport:
    """
    Format OpenTelemetry pour export.

    Invariant:
        OBS_004: Format standard OpenTelemetry
    """

    resource_spans: List[Dict[str, Any]]
    schema_url: str = "https://opentelemetry.io/schemas/1.21.0"


@dataclass
class TraceRetentionPolicy:
    """
    Politique de rétention des traces.

    Invariant:
        OBS_005: retention_days >= 30
    """

    retention_days: int = 30  # OBS_005
    max_spans_per_trace: int = 1000
    archive_after_days: int = 7


class SpanNotFoundError(Exception):
    """Span non trouvé."""

    pass


class SpanAlreadyEndedError(Exception):
    """Span déjà terminé."""

    pass


class TracingError(Exception):
    """Erreur générale de tracing."""

    pass


class ISpanExporter(ABC):
    """
    Interface export traces.

    Invariant:
        OBS_004: Export format OpenTelemetry
    """

    @abstractmethod
    def export(self, spans: List[Span]) -> bool:
        """
        Exporte spans format OpenTelemetry.

        Args:
            spans: Liste de spans à exporter

        Returns:
            True si export réussi

        Invariant:
            OBS_004: Format OpenTelemetry standard
        """
        pass


class ITraceStore(ABC):
    """Interface stockage traces."""

    @abstractmethod
    def store(self, span: Span) -> None:
        """
        Stocke span.

        Args:
            span: Span à stocker
        """
        pass

    @abstractmethod
    def get_by_trace_id(self, trace_id: str) -> List[Span]:
        """
        Récupère tous spans d'une trace.

        Args:
            trace_id: ID de la trace

        Returns:
            Liste des spans de la trace
        """
        pass

    @abstractmethod
    def cleanup_expired(self, retention_days: int) -> int:
        """
        Supprime spans expirés.

        Args:
            retention_days: Nombre de jours de rétention

        Returns:
            Nombre de spans supprimés

        Invariant:
            OBS_005: Retention 30 jours minimum
        """
        pass


class InMemoryTraceStore(ITraceStore):
    """
    Stockage traces en mémoire (pour tests).

    Implémente ITraceStore avec stockage en mémoire.
    """

    def __init__(self) -> None:
        """Initialise le store."""
        self._spans: Dict[str, Span] = {}
        self._by_trace: Dict[str, List[str]] = {}

    def store(self, span: Span) -> None:
        """Stocke span."""
        self._spans[span.span_id] = span
        if span.trace_id not in self._by_trace:
            self._by_trace[span.trace_id] = []
        if span.span_id not in self._by_trace[span.trace_id]:
            self._by_trace[span.trace_id].append(span.span_id)

    def get_by_trace_id(self, trace_id: str) -> List[Span]:
        """Récupère tous spans d'une trace."""
        span_ids = self._by_trace.get(trace_id, [])
        return [self._spans[sid] for sid in span_ids if sid in self._spans]

    def cleanup_expired(self, retention_days: int) -> int:
        """Supprime spans expirés."""
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(days=retention_days)
        expired_ids = []

        for span_id, span in self._spans.items():
            if span.start_time < cutoff:
                expired_ids.append(span_id)

        for span_id in expired_ids:
            span = self._spans.pop(span_id)
            if span.trace_id in self._by_trace:
                if span_id in self._by_trace[span.trace_id]:
                    self._by_trace[span.trace_id].remove(span_id)
                if not self._by_trace[span.trace_id]:
                    del self._by_trace[span.trace_id]

        return len(expired_ids)

    def clear(self) -> None:
        """Efface tous les spans (pour tests)."""
        self._spans.clear()
        self._by_trace.clear()


class TracingManager:
    """
    Gestion tracing distribué format OpenTelemetry.

    Invariants:
        OBS_004: Traces exportées format OpenTelemetry
        OBS_005: Retention traces 30 jours minimum
        OBS_006: Latence chaque span mesurée et stockée
        OBS_007: Erreurs tracées avec stack trace complet
    """

    DEFAULT_RETENTION_DAYS: int = 30  # OBS_005
    OPENTELEMETRY_SCHEMA_URL: str = "https://opentelemetry.io/schemas/1.21.0"

    def __init__(
        self,
        correlation_manager: ICorrelationManager,
        exporter: Optional[ISpanExporter] = None,
        store: Optional[ITraceStore] = None,
        service_name: str = "zynaxia",
    ) -> None:
        """
        Initialise le TracingManager.

        Args:
            correlation_manager: Gestionnaire correlation IDs
            exporter: Exporteur de spans (optionnel)
            store: Store de spans (optionnel, défaut InMemory)
            service_name: Nom du service
        """
        self._correlation = correlation_manager
        self._exporter = exporter
        self._store = store or InMemoryTraceStore()
        self._service_name = service_name
        self._active_spans: Dict[str, Span] = {}
        self._completed_spans: List[Span] = []
        self._retention_policy = TraceRetentionPolicy()

    def start_span(
        self,
        name: str,
        parent_span_id: Optional[str] = None,
        attributes: Optional[Dict[str, Any]] = None,
        trace_id: Optional[str] = None,
    ) -> Span:
        """
        Démarre un nouveau span.

        Args:
            name: Nom du span
            parent_span_id: ID du span parent (optionnel)
            attributes: Attributs du span (optionnel)
            trace_id: ID de trace existant (optionnel)

        Returns:
            Span créé

        Raises:
            ValueError: Si name est vide

        Invariant:
            OBS_006: Enregistre start_time pour calcul latence
        """
        if not name or not name.strip():
            raise ValueError("Span name cannot be empty")

        # Générer IDs
        span_id = str(uuid.uuid4())

        # Utiliser trace_id fourni ou celui du parent ou en générer un
        if trace_id is None:
            if parent_span_id and parent_span_id in self._active_spans:
                trace_id = self._active_spans[parent_span_id].trace_id
            elif parent_span_id:
                # Check completed spans
                for s in self._completed_spans:
                    if s.span_id == parent_span_id:
                        trace_id = s.trace_id
                        break
            if trace_id is None:
                trace_id = str(uuid.uuid4())

        # Obtenir correlation_id courant
        correlation_id = self._correlation.get_current()
        if correlation_id is None:
            correlation_id = self._correlation.generate()
            self._correlation.set_current(correlation_id)

        # Créer span avec timing précis (OBS_006)
        span = Span(
            span_id=span_id,
            trace_id=trace_id,
            correlation_id=correlation_id,
            name=name,
            service_name=self._service_name,
            start_time=datetime.now(timezone.utc),
            parent_span_id=parent_span_id,
            attributes=attributes or {},
            _start_perf_counter=time.perf_counter(),
        )

        # Stocker comme actif
        self._active_spans[span_id] = span

        return span

    def end_span(self, span_id: str) -> Span:
        """
        Termine un span.

        Args:
            span_id: ID du span à terminer

        Returns:
            Span terminé

        Raises:
            SpanNotFoundError: Si span non trouvé
            SpanAlreadyEndedError: Si span déjà terminé

        Invariant:
            OBS_006: Calcule duration_ms
        """
        if not span_id:
            raise ValueError("span_id cannot be empty")

        # Vérifier si déjà terminé
        for s in self._completed_spans:
            if s.span_id == span_id:
                raise SpanAlreadyEndedError(f"Span {span_id} already ended")

        # Récupérer span actif
        span = self._active_spans.pop(span_id, None)
        if span is None:
            raise SpanNotFoundError(f"Span {span_id} not found")

        # Calculer durée (OBS_006)
        end_perf = time.perf_counter()
        if span._start_perf_counter is not None:
            span.duration_ms = (end_perf - span._start_perf_counter) * 1000

        span.end_time = datetime.now(timezone.utc)

        # Définir status OK si pas d'erreur
        if span.status == SpanStatus.UNSET:
            span.status = SpanStatus.OK

        # Ajouter aux complétés
        self._completed_spans.append(span)

        # Stocker
        self._store.store(span)

        return span

    def record_error(
        self,
        span_id: str,
        error: Exception,
        set_status: bool = True,
    ) -> None:
        """
        Enregistre erreur avec stack trace complet.

        Args:
            span_id: ID du span
            error: Exception à enregistrer
            set_status: Définir status ERROR (défaut True)

        Raises:
            SpanNotFoundError: Si span non trouvé

        Invariant:
            OBS_007: Stack trace complet enregistré
        """
        span = self._active_spans.get(span_id)
        if span is None:
            raise SpanNotFoundError(f"Span {span_id} not found")

        # Capturer stack trace complet (OBS_007)
        span.error_stack_trace = traceback.format_exc()

        # Ajouter détails erreur dans attributs
        span.attributes["error.type"] = type(error).__name__
        span.attributes["error.message"] = str(error)

        # Ajouter événement erreur
        self.add_event(
            span_id,
            "exception",
            {
                "exception.type": type(error).__name__,
                "exception.message": str(error),
                "exception.stacktrace": span.error_stack_trace,
            },
        )

        if set_status:
            span.status = SpanStatus.ERROR

    def add_event(
        self,
        span_id: str,
        name: str,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Ajoute événement au span.

        Args:
            span_id: ID du span
            name: Nom de l'événement
            attributes: Attributs de l'événement (optionnel)

        Raises:
            SpanNotFoundError: Si span non trouvé
            ValueError: Si name vide
        """
        if not name or not name.strip():
            raise ValueError("Event name cannot be empty")

        span = self._active_spans.get(span_id)
        if span is None:
            raise SpanNotFoundError(f"Span {span_id} not found")

        event = SpanEvent(
            name=name,
            timestamp=datetime.now(timezone.utc),
            attributes=attributes or {},
        )
        span.events.append(event)

    def set_attribute(self, span_id: str, key: str, value: Any) -> None:
        """
        Définit un attribut sur le span.

        Args:
            span_id: ID du span
            key: Clé de l'attribut
            value: Valeur de l'attribut

        Raises:
            SpanNotFoundError: Si span non trouvé
        """
        span = self._active_spans.get(span_id)
        if span is None:
            raise SpanNotFoundError(f"Span {span_id} not found")

        span.attributes[key] = value

    def export_to_opentelemetry(
        self, spans: Optional[List[Span]] = None
    ) -> OpenTelemetryExport:
        """
        Convertit spans en format OpenTelemetry.

        Args:
            spans: Liste de spans (défaut: completed_spans)

        Returns:
            OpenTelemetryExport avec resource_spans

        Invariant:
            OBS_004: Format OpenTelemetry standard
        """
        if spans is None:
            spans = self._completed_spans

        # Grouper par service
        by_service: Dict[str, List[Dict[str, Any]]] = {}

        for span in spans:
            if span.service_name not in by_service:
                by_service[span.service_name] = []

            # Convertir span en format OTLP
            otlp_span = self._span_to_otlp(span)
            by_service[span.service_name].append(otlp_span)

        # Construire resource_spans
        resource_spans = []
        for service_name, service_spans in by_service.items():
            resource_span = {
                "resource": {
                    "attributes": [
                        {"key": "service.name", "value": {"stringValue": service_name}}
                    ]
                },
                "scopeSpans": [
                    {
                        "scope": {"name": "zynaxia.tracing", "version": "1.0.0"},
                        "spans": service_spans,
                    }
                ],
            }
            resource_spans.append(resource_span)

        return OpenTelemetryExport(
            resource_spans=resource_spans,
            schema_url=self.OPENTELEMETRY_SCHEMA_URL,
        )

    def _span_to_otlp(self, span: Span) -> Dict[str, Any]:
        """
        Convertit un Span en format OTLP.

        Args:
            span: Span à convertir

        Returns:
            Dict au format OTLP
        """
        # Convertir timestamps en nanosecondes
        start_ns = int(span.start_time.timestamp() * 1e9)
        end_ns = int(span.end_time.timestamp() * 1e9) if span.end_time else start_ns

        # Convertir attributs
        attributes = []
        for key, value in span.attributes.items():
            attr = {"key": key}
            if isinstance(value, str):
                attr["value"] = {"stringValue": value}
            elif isinstance(value, bool):
                attr["value"] = {"boolValue": value}
            elif isinstance(value, int):
                attr["value"] = {"intValue": str(value)}
            elif isinstance(value, float):
                attr["value"] = {"doubleValue": value}
            else:
                attr["value"] = {"stringValue": str(value)}
            attributes.append(attr)

        # Ajouter correlation_id comme attribut
        attributes.append(
            {"key": "correlation_id", "value": {"stringValue": span.correlation_id}}
        )

        # Convertir événements
        events = []
        for event in span.events:
            event_attrs = []
            for key, value in event.attributes.items():
                if isinstance(value, str):
                    event_attrs.append(
                        {"key": key, "value": {"stringValue": value}}
                    )
                else:
                    event_attrs.append(
                        {"key": key, "value": {"stringValue": str(value)}}
                    )

            events.append(
                {
                    "name": event.name,
                    "timeUnixNano": str(int(event.timestamp.timestamp() * 1e9)),
                    "attributes": event_attrs,
                }
            )

        # Mapper status
        status_code = 0  # UNSET
        if span.status == SpanStatus.OK:
            status_code = 1
        elif span.status == SpanStatus.ERROR:
            status_code = 2

        otlp = {
            "traceId": span.trace_id.replace("-", ""),
            "spanId": span.span_id.replace("-", "")[:16],
            "name": span.name,
            "kind": 1,  # INTERNAL
            "startTimeUnixNano": str(start_ns),
            "endTimeUnixNano": str(end_ns),
            "attributes": attributes,
            "events": events,
            "status": {"code": status_code},
        }

        if span.parent_span_id:
            otlp["parentSpanId"] = span.parent_span_id.replace("-", "")[:16]

        # Ajouter duration_ms comme attribut si présent (OBS_006)
        if span.duration_ms is not None:
            otlp["attributes"].append(
                {"key": "duration_ms", "value": {"doubleValue": span.duration_ms}}
            )

        return otlp

    def get_span(self, span_id: str) -> Optional[Span]:
        """
        Récupère span par ID.

        Args:
            span_id: ID du span

        Returns:
            Span ou None si non trouvé
        """
        # Vérifier actifs
        if span_id in self._active_spans:
            return self._active_spans[span_id]

        # Vérifier complétés
        for span in self._completed_spans:
            if span.span_id == span_id:
                return span

        return None

    def get_trace(self, trace_id: str) -> List[Span]:
        """
        Récupère tous spans d'une trace.

        Args:
            trace_id: ID de la trace

        Returns:
            Liste des spans de la trace
        """
        result = []

        # Actifs
        for span in self._active_spans.values():
            if span.trace_id == trace_id:
                result.append(span)

        # Complétés
        for span in self._completed_spans:
            if span.trace_id == trace_id:
                result.append(span)

        return result

    def cleanup_old_spans(self, retention_days: Optional[int] = None) -> int:
        """
        Supprime spans plus anciens que la rétention.

        Args:
            retention_days: Jours de rétention (défaut: 30)

        Returns:
            Nombre de spans supprimés

        Invariant:
            OBS_005: Retention minimum 30 jours
        """
        days = retention_days or self.DEFAULT_RETENTION_DAYS
        if days < self.DEFAULT_RETENTION_DAYS:
            days = self.DEFAULT_RETENTION_DAYS  # OBS_005: minimum 30 jours

        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(days=days)

        # Filtrer completed_spans
        original_count = len(self._completed_spans)
        self._completed_spans = [
            span for span in self._completed_spans if span.start_time >= cutoff
        ]
        removed_count = original_count - len(self._completed_spans)

        # Cleanup dans le store aussi
        store_removed = self._store.cleanup_expired(days)

        return removed_count + store_removed

    def is_span_expired(self, span: Span, retention_days: Optional[int] = None) -> bool:
        """
        Vérifie si span dépasse la rétention.

        Args:
            span: Span à vérifier
            retention_days: Jours de rétention (défaut: 30)

        Returns:
            True si span expiré

        Invariant:
            OBS_005: Vérification basée sur retention 30j
        """
        days = retention_days or self.DEFAULT_RETENTION_DAYS
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(days=days)
        return span.start_time < cutoff

    def get_retention_policy(self) -> TraceRetentionPolicy:
        """Retourne la politique de rétention."""
        return self._retention_policy

    def set_retention_policy(self, policy: TraceRetentionPolicy) -> None:
        """
        Définit la politique de rétention.

        Args:
            policy: Nouvelle politique

        Raises:
            ValueError: Si retention_days < 30

        Invariant:
            OBS_005: Minimum 30 jours
        """
        if policy.retention_days < self.DEFAULT_RETENTION_DAYS:
            raise ValueError(
                f"retention_days must be >= {self.DEFAULT_RETENTION_DAYS} (OBS_005)"
            )
        self._retention_policy = policy

    def get_active_spans(self) -> List[Span]:
        """Retourne les spans actifs."""
        return list(self._active_spans.values())

    def get_completed_spans(self) -> List[Span]:
        """Retourne les spans complétés."""
        return list(self._completed_spans)

    def clear(self) -> None:
        """Efface tous les spans (pour tests)."""
        self._active_spans.clear()
        self._completed_spans.clear()
        if isinstance(self._store, InMemoryTraceStore):
            self._store.clear()


@contextmanager
def trace_span(
    tracing: TracingManager,
    name: str,
    **attributes: Any,
) -> Generator[Span, None, None]:
    """
    Context manager pour tracing automatique.

    Usage:
        with trace_span(tracing, "db_query", table="users") as span:
            # code tracé
            pass

    Args:
        tracing: TracingManager
        name: Nom du span
        **attributes: Attributs du span

    Yields:
        Span créé

    Invariants:
        OBS_006: Mesure automatiquement la latence
        OBS_007: Capture automatiquement les erreurs
    """
    span = tracing.start_span(name, attributes=attributes if attributes else None)
    try:
        yield span
    except Exception as e:
        tracing.record_error(span.span_id, e)
        raise
    finally:
        tracing.end_span(span.span_id)
