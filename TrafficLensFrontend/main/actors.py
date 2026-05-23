import threading
import time

import pykka
import structlog
from django.db import close_old_connections

log = structlog.get_logger(__name__)

_CLEANUP_INTERVAL = 300  # seconds between guest-file cleanup runs
_cleanup_lock = threading.Lock()
_last_cleanup = 0.0


class PcapAnalyzerActor(pykka.ThreadingActor):
    """Fire-and-forget actor that parses a PCAP and persists results to the DB."""

    def on_receive(self, message: dict) -> None:
        close_old_connections()
        pcap_id = message['pcap_id']
        log.info('pcap.analyze.start', pcap_id=pcap_id)
        try:
            # Imported here to avoid circular imports at module load time
            from main.models import PcapFile
            from trafficlens_core import analyze_pcap_bytes
            from main.views import _persist_analysis

            upload = PcapFile.objects.get(pk=pcap_id)
            with upload.file.open('rb') as f:
                packets = analyze_pcap_bytes(f.read())
            _persist_analysis(upload, packets)
            log.info('pcap.analyzed', pcap_id=pcap_id, packet_count=len(packets))
        except Exception:
            log.exception('pcap.analyze_failed', pcap_id=pcap_id)
        finally:
            self.stop()


class EmailActor(pykka.ThreadingActor):
    """Fire-and-forget actor that sends a single email off the request thread."""

    def on_receive(self, message: dict) -> None:
        close_old_connections()
        to = message.get('to', [])
        try:
            from django.core.mail import EmailMessage
            EmailMessage(message['subject'], message['body'], to=to).send()
            log.info('email.sent', to=to, subject=message['subject'])
        except Exception:
            log.exception('email.send_failed', to=to)
        finally:
            self.stop()


class CleanupActor(pykka.ThreadingActor):
    """Throttled actor that removes stale guest PCAP files.

    At most one cleanup run every _CLEANUP_INTERVAL seconds even if many
    guest_login requests arrive concurrently.
    """

    def on_receive(self, message: dict) -> None:  # noqa: ARG002
        global _last_cleanup
        close_old_connections()

        now = time.monotonic()
        with _cleanup_lock:
            if now - _last_cleanup < _CLEANUP_INTERVAL:
                log.debug('guest.cleanup.throttled', next_run_in_s=round(_CLEANUP_INTERVAL - (now - _last_cleanup)))
                return
            _last_cleanup = now

        try:
            from django.contrib.sessions.models import Session
            from main.models import PcapFile

            active_keys = set(Session.objects.values_list('session_key', flat=True))
            from main.views import _delete_packet_cache
            stale = PcapFile.objects.filter(user=None).exclude(session_key__in=active_keys)
            count = stale.count()
            for f in stale:
                _delete_packet_cache(f)
                f.file.delete(save=False)
                f.delete()
            if count:
                log.info('guest.cleanup', removed=count)
        except Exception:
            log.exception('guest.cleanup_failed')
        finally:
            self.stop()
